/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type ESXiClusterStore struct {
	Store *DataStore
}

func NewESXiCLusterStore(store *DataStore) *ESXiClusterStore {
	return &ESXiClusterStore{store}
}

func (t *ESXiClusterStore) Create(esxiCLuster *hvs.ESXiCluster) (*hvs.ESXiCluster, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:Create() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Create() Leaving")

	dbESXiCluster := esxiCluster{
		Id:               uuid.New(),
		ConnectionString: esxiCLuster.ConnectionString,
		ClusterName:      esxiCLuster.ClusterName,
	}

	if err := t.Store.Db.Create(&dbESXiCluster).Error; err != nil {
		return esxiCLuster, errors.Wrap(err, "postgres/esxi_cluster_store:Create() Failed to create ESXi cluster")
	}
	esxiCLuster.Id = dbESXiCluster.Id

	//TODO : Add hosts in the cluster to host table
	return esxiCLuster, nil
}

func (t *ESXiClusterStore) Retrieve(id uuid.UUID) (*hvs.ESXiCluster, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Retrieve() Leaving")

	cluster := hvs.ESXiCluster{}
	row := t.Store.Db.Model(&esxiCluster{}).Where(&esxiCluster{Id: id}).Row()
	if err := row.Scan(&cluster.Id, &cluster.ConnectionString, &cluster.ClusterName); err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Retrieve() Failed to scan record")
	}

	//TODO : Get the list of hosts from host table
	return &cluster, nil
}

func (t *ESXiClusterStore) Search(ecFilter *models.ESXiClusterFilterCriteria) (*hvs.ESXiClusterCollection, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:Search() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Search() Leaving")

	tx := buildESXiClusterSearchQuery(t.Store.Db, ecFilter)
	if tx == nil {
		return nil, errors.New("postgres/esxi_cluster_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Search() Failed to retrieve records from db")
	}
	defer rows.Close()

	clusterCollection := hvs.ESXiClusterCollection{}
	for rows.Next() {
		cluster := hvs.ESXiCluster{}
		if err := rows.Scan(&cluster.Id, &cluster.ConnectionString, &cluster.ClusterName); err != nil {
			return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Search() Failed to scan record")
		}
		clusterCollection.ESXiCluster = append(clusterCollection.ESXiCluster, &cluster)
	}

	//TODO : Get the list of hosts from host table
	return &clusterCollection, nil
}

func (t *ESXiClusterStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/esxi_cluster_store:Delete() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Delete() Leaving")

	if err := t.Store.Db.Delete(&esxiCluster{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/esxi_cluster_store:Delete() Failed to delete ESXi cluster")
	}
	return nil
}

//Helper function to build the query object for a ESXi cluster search.
func buildESXiClusterSearchQuery(tx *gorm.DB, criteria *models.ESXiClusterFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/esxi_cluster_store:buildESXiClusterSearchQuery() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:buildESXiClusterSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&esxiCluster{})
	if criteria == nil {
		return tx
	}

	if criteria.Id != uuid.Nil {
		tx = tx.Where("id = ?", criteria.Id)
	} else if criteria.ClusterName != "" {
		tx = tx.Where("cluster_name = ?", criteria.ClusterName)
	}

	return tx
}
