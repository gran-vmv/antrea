// Copyright 2024 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	crdv1alpha1 "antrea.io/antrea/pkg/apis/crd/v1alpha1"
	versioned "antrea.io/antrea/pkg/client/clientset/versioned"
	internalinterfaces "antrea.io/antrea/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "antrea.io/antrea/pkg/client/listers/crd/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// NodeLatencyMonitorInformer provides access to a shared informer and lister for
// NodeLatencyMonitors.
type NodeLatencyMonitorInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.NodeLatencyMonitorLister
}

type nodeLatencyMonitorInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewNodeLatencyMonitorInformer constructs a new informer for NodeLatencyMonitor type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewNodeLatencyMonitorInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredNodeLatencyMonitorInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredNodeLatencyMonitorInformer constructs a new informer for NodeLatencyMonitor type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredNodeLatencyMonitorInformer(client versioned.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CrdV1alpha1().NodeLatencyMonitors().List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.CrdV1alpha1().NodeLatencyMonitors().Watch(context.TODO(), options)
			},
		},
		&crdv1alpha1.NodeLatencyMonitor{},
		resyncPeriod,
		indexers,
	)
}

func (f *nodeLatencyMonitorInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredNodeLatencyMonitorInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *nodeLatencyMonitorInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&crdv1alpha1.NodeLatencyMonitor{}, f.defaultInformer)
}

func (f *nodeLatencyMonitorInformer) Lister() v1alpha1.NodeLatencyMonitorLister {
	return v1alpha1.NewNodeLatencyMonitorLister(f.Informer().GetIndexer())
}
