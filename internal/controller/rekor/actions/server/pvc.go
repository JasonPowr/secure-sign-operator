package server

import (
	"context"
	"fmt"

	"github.com/securesign/operator/internal/controller/common/action"
	"github.com/securesign/operator/internal/controller/common/utils"
	k8sutils "github.com/securesign/operator/internal/controller/common/utils/kubernetes"
	"github.com/securesign/operator/internal/controller/common/utils/kubernetes/ensure"
	"github.com/securesign/operator/internal/controller/constants"
	"github.com/securesign/operator/internal/controller/labels"
	"github.com/securesign/operator/internal/controller/rekor/actions"
	"golang.org/x/exp/maps"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	rhtasv1alpha1 "github.com/securesign/operator/api/v1alpha1"
)

const PvcNameFormat = "rekor-%s-pvc"

func NewCreatePvcAction() action.Action[*rhtasv1alpha1.Rekor] {
	return &createPvcAction{}
}

type createPvcAction struct {
	action.BaseAction
}

func (i createPvcAction) Name() string {
	return "create PVC"
}

func (i createPvcAction) CanHandle(_ context.Context, instance *rhtasv1alpha1.Rekor) bool {
	c := meta.FindStatusCondition(instance.Status.Conditions, constants.Ready)
	return c.Reason == constants.Creating && instance.Status.PvcName == ""
}

func (i createPvcAction) Handle(ctx context.Context, instance *rhtasv1alpha1.Rekor) *action.Result {
	var (
		result controllerutil.OperationResult
		err    error
	)
	if instance.Spec.Pvc.Name != "" {
		instance.Status.PvcName = instance.Spec.Pvc.Name
		return i.StatusUpdate(ctx, instance)
	}

	if instance.Spec.Pvc.Size == nil {
		return i.Error(ctx, reconcile.TerminalError(fmt.Errorf("PVC size is not set")), instance)
	}

	// PVC does not exist, create a new one
	i.Logger.V(1).Info("Creating new PVC")

	pvc := &v1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf(PvcNameFormat, instance.Name),
			Namespace: instance.Namespace,
		},
	}

	l := labels.For(actions.ServerComponentName, actions.ServerDeploymentName, instance.Name)
	if result, err = k8sutils.CreateOrUpdate(ctx, i.Client, pvc,
		k8sutils.EnsurePVCSpec(instance.Spec.Pvc),
		ensure.Optional[*v1.PersistentVolumeClaim](!utils.OptionalBool(instance.Spec.Pvc.Retain), ensure.ControllerReference[*v1.PersistentVolumeClaim](instance, i.Client)),
		ensure.Labels[*v1.PersistentVolumeClaim](maps.Keys(l), l),
	); err != nil {
		// do not terminate the deployment - retry with exponential backoff
		return i.Error(ctx, fmt.Errorf("could not create DB PVC: %w", err), instance)
	}

	if result != controllerutil.OperationResultNone {
		i.Recorder.Event(instance, v1.EventTypeNormal, "PersistentVolumeCreated", "New PersistentVolume created")
	}

	instance.Status.PvcName = pvc.Name
	return i.StatusUpdate(ctx, instance)
}
