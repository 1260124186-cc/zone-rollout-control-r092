package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

// ExpireLeases transitions claimed leases whose deadline has passed to
// expired and returns their nodes to ready. It is a pure time-driven
// maintenance step that records no caller-initiated operation.
func ExpireLeases(state *State, now time.Time) int {
	count := 0
	for leaseID, lease := range state.Leases {
		if lease.State != LeaseClaimed || lease.ExpiresAt.After(now) {
			continue
		}
		finishedAt := now.UTC()
		lease.State = LeaseExpired
		lease.FinishedAt = &finishedAt
		state.Leases[leaseID] = lease
		if node, ok := state.Nodes[lease.NodeID]; ok && node.State == NodeLeased {
			node.State = NodeReady
			node.Version++
			node.UpdatedAt = now.UTC()
			state.Nodes[node.ID] = node
		}
		count++
	}
	return count
}

func timePointer(value time.Time) *time.Time {
	return &value
}

type credentialContextKey struct{}

// WithCredential records the plan operation credential presented by the caller
// so that plan-scoped write flows can authorize the submitted request.
func WithCredential(ctx context.Context, secret string) context.Context {
	if secret == "" {
		return ctx
	}
	return context.WithValue(ctx, credentialContextKey{}, secret)
}

// CredentialFrom returns the plan operation credential carried by the request,
// or an empty string when the caller presented none.
func CredentialFrom(ctx context.Context) string {
	value, _ := ctx.Value(credentialContextKey{}).(string)
	return value
}

// ValidateCredentialSecret checks the shape of a caller-provided credential.
func ValidateCredentialSecret(secret string) error {
	if err := validateRequestKey(secret); err != nil {
		return Validation("plan credential is invalid", map[string]any{
			"credential": err.Error(),
		})
	}
	return nil
}

// ActivePlanCredential verifies that the presented secret is the plan's
// currently active credential. Retired credentials never match, so they can
// neither authorize new writes nor read plan data after rotation.
func ActivePlanCredential(
	secret string,
	plan RolloutPlan,
	credentials map[string]PlanCredential,
) (PlanCredential, bool) {
	if secret == "" || plan.ActiveCredentialID == "" {
		return PlanCredential{}, false
	}
	credential, ok := credentials[plan.ActiveCredentialID]
	if !ok || credential.PlanID != plan.ID || credential.Retired() || credential.Secret != secret {
		return PlanCredential{}, false
	}
	return credential, true
}

// ReplayPlanCredential authorizes retrieving a previously stored idempotent
// result. The presented secret must be either the plan's currently active
// credential or the exact credential that authorized the original request
// (which may have been retired by a later rotation).
func ReplayPlanCredential(
	secret string,
	plan RolloutPlan,
	recordCredentialID string,
	credentials map[string]PlanCredential,
) (PlanCredential, bool) {
	if credential, ok := ActivePlanCredential(secret, plan, credentials); ok {
		return credential, true
	}
	if secret == "" || recordCredentialID == "" {
		return PlanCredential{}, false
	}
	credential, ok := credentials[recordCredentialID]
	if !ok || credential.PlanID != plan.ID || credential.Secret != secret {
		return PlanCredential{}, false
	}
	return credential, true
}

// UnauthorizedPlanWrite builds the stable error returned when a request
// cannot be authorized for the target plan.
func UnauthorizedPlanWrite(planID string) *DomainError {
	return NewError(CodeUnauthorized, "plan credential is not authorized for this write", map[string]any{
		"plan_id": planID,
	})
}
