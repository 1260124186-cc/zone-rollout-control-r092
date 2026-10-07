package workflowprobe

import (
	"net/http"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runCredentialRotation() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	if _, err := enrollNode(harness, "resolver-rotate-01", "north"); err != nil {
		return err
	}
	if _, err := enrollNode(harness, "resolver-rotate-02", "north"); err != nil {
		return err
	}
	plan, revision, err := createActivePlan(harness, "rotate.example", 7001, 1, 0.5, 100)
	if err != nil {
		return err
	}
	credentialA := harness.credential

	first, err := allocate(harness, plan.ID, "rotate-lease-0001", "north", 1)
	if err != nil {
		return err
	}
	if len(first.LeaseIDs) != 1 {
		return ensure(false, "first lease group must contain one lease")
	}
	replay, err := allocate(harness, plan.ID, "rotate-lease-0001", "north", 1)
	if err != nil {
		return err
	}
	if replay.ID != first.ID {
		return ensure(false, "lease replay before rotation returned another group")
	}

	harness.credential = ""
	if _, err := allocate(harness, plan.ID, "rotate-lease-0001", "north", 1); err != nil {
		if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
			return err
		}
	} else {
		return ensure(false, "lease replay without a credential must be rejected")
	}
	harness.credential = "workflow-credential-9999"
	if _, err := allocate(harness, plan.ID, "rotate-lease-0001", "north", 1); err != nil {
		if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
			return err
		}
	} else {
		return ensure(false, "lease replay with an unknown credential must be rejected")
	}

	harness.credential = ""
	err = harness.call(http.MethodPost, "/v1/plans/"+plan.ID+"/credential", nil, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}
	harness.credential = "workflow-credential-9999"
	err = harness.call(http.MethodPost, "/v1/plans/"+plan.ID+"/credential", nil, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}

	harness.credential = credentialA
	var rotated domain.PlanCredential
	if err := harness.call(http.MethodPost, "/v1/plans/"+plan.ID+"/credential", nil, &rotated); err != nil {
		return err
	}
	credentialB := rotated.Secret
	if credentialB == "" || credentialB == credentialA {
		return ensure(false, "rotation did not issue a distinct credential")
	}

	if _, err := allocate(harness, plan.ID, "rotate-lease-0002", "north", 1); err != nil {
		if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
			return err
		}
	} else {
		return ensure(false, "retired credential authorized a new lease allocation")
	}
	replayed, err := allocate(harness, plan.ID, "rotate-lease-0001", "north", 1)
	if err != nil {
		return err
	}
	if replayed.ID != first.ID {
		return ensure(false, "lease replay with the retired credential lost the original group")
	}
	harness.credential = credentialB
	replayed, err = allocate(harness, plan.ID, "rotate-lease-0001", "north", 1)
	if err != nil {
		return err
	}
	if replayed.ID != first.ID {
		return ensure(false, "lease replay with the active credential lost the original group")
	}
	second, err := allocate(harness, plan.ID, "rotate-lease-0002", "north", 1)
	if err != nil {
		return err
	}
	if len(second.LeaseIDs) != 1 {
		return ensure(false, "second lease group must contain one lease")
	}

	harness.credential = credentialA
	_, err = submitProbe(harness, second.LeaseIDs[0], "rotate-probe-0001", true, revision.Serial, 10)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}
	harness.credential = credentialB
	stored, err := submitProbe(harness, second.LeaseIDs[0], "rotate-probe-0001", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	harness.credential = credentialA
	probeReplay, err := submitProbe(harness, second.LeaseIDs[0], "rotate-probe-0001", true, revision.Serial, 10)
	if err != nil {
		return err
	}
	if probeReplay.ID != stored.ID {
		return ensure(false, "probe replay with a known credential returned another probe")
	}
	harness.credential = ""
	_, err = submitProbe(harness, second.LeaseIDs[0], "rotate-probe-0001", true, revision.Serial, 10)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}

	harness.credential = credentialA
	err = harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "rotate-assess-0001",
	}, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}
	harness.credential = credentialB
	var assessment domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "rotate-assess-0001",
	}, &assessment); err != nil {
		return err
	}
	harness.credential = credentialA
	var assessmentReplay domain.RolloutAssessment
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "rotate-assess-0001",
	}, &assessmentReplay); err != nil {
		return err
	}
	if assessmentReplay.ID != assessment.ID {
		return ensure(false, "assessment replay with the retired credential lost the original result")
	}
	harness.credential = "workflow-credential-9999"
	err = harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/assessments", domain.AssessmentInput{
		RequestKey: "rotate-assess-0001",
	}, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}

	harness.credential = ""
	err = harness.call(http.MethodPatch, "/v1/leases/"+first.LeaseIDs[0]+"/release", nil, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}
	harness.credential = credentialA
	err = harness.call(http.MethodPatch, "/v1/leases/"+first.LeaseIDs[0]+"/release", nil, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}
	harness.credential = credentialB
	var released domain.NodeLease
	if err := harness.call(http.MethodPatch, "/v1/leases/"+first.LeaseIDs[0]+"/release", nil, &released); err != nil {
		return err
	}
	if released.State != domain.LeaseReleased {
		return ensure(false, "lease release with the active credential did not update state")
	}

	harness.credential = credentialA
	err = harness.call(http.MethodPost, "/v1/plans/"+plan.ID+"/credential", nil, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}

	var current domain.RolloutPlan
	harness.credential = credentialB
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &current); err != nil {
		return err
	}
	harness.credential = credentialA
	err = harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": current.Version,
	}, nil)
	if err := expectFailure(err, http.StatusForbidden, string(domain.CodeUnauthorized)); err != nil {
		return err
	}
	harness.credential = credentialB
	var completed domain.RolloutPlan
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": current.Version,
	}, &completed); err != nil {
		return err
	}
	if completed.State != domain.PlanCompleted {
		return ensure(false, "plan completion with the active credential failed")
	}
	return nil
}
