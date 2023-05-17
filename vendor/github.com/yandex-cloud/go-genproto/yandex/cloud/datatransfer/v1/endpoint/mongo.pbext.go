// Code generated by protoc-gen-goext. DO NOT EDIT.

package endpoint

func (m *OnPremiseMongo) SetHosts(v []string) {
	m.Hosts = v
}

func (m *OnPremiseMongo) SetPort(v int64) {
	m.Port = v
}

func (m *OnPremiseMongo) SetTlsMode(v *TLSMode) {
	m.TlsMode = v
}

func (m *OnPremiseMongo) SetReplicaSet(v string) {
	m.ReplicaSet = v
}

type MongoConnectionOptions_Address = isMongoConnectionOptions_Address

func (m *MongoConnectionOptions) SetAddress(v MongoConnectionOptions_Address) {
	m.Address = v
}

func (m *MongoConnectionOptions) SetMdbClusterId(v string) {
	m.Address = &MongoConnectionOptions_MdbClusterId{
		MdbClusterId: v,
	}
}

func (m *MongoConnectionOptions) SetOnPremise(v *OnPremiseMongo) {
	m.Address = &MongoConnectionOptions_OnPremise{
		OnPremise: v,
	}
}

func (m *MongoConnectionOptions) SetUser(v string) {
	m.User = v
}

func (m *MongoConnectionOptions) SetPassword(v *Secret) {
	m.Password = v
}

func (m *MongoConnectionOptions) SetAuthSource(v string) {
	m.AuthSource = v
}

type MongoConnection_Connection = isMongoConnection_Connection

func (m *MongoConnection) SetConnection(v MongoConnection_Connection) {
	m.Connection = v
}

func (m *MongoConnection) SetConnectionOptions(v *MongoConnectionOptions) {
	m.Connection = &MongoConnection_ConnectionOptions{
		ConnectionOptions: v,
	}
}

func (m *MongoCollection) SetDatabaseName(v string) {
	m.DatabaseName = v
}

func (m *MongoCollection) SetCollectionName(v string) {
	m.CollectionName = v
}

func (m *MongoSource) SetConnection(v *MongoConnection) {
	m.Connection = v
}

func (m *MongoSource) SetSubnetId(v string) {
	m.SubnetId = v
}

func (m *MongoSource) SetSecurityGroups(v []string) {
	m.SecurityGroups = v
}

func (m *MongoSource) SetCollections(v []*MongoCollection) {
	m.Collections = v
}

func (m *MongoSource) SetExcludedCollections(v []*MongoCollection) {
	m.ExcludedCollections = v
}

func (m *MongoSource) SetSecondaryPreferredMode(v bool) {
	m.SecondaryPreferredMode = v
}

func (m *MongoTarget) SetConnection(v *MongoConnection) {
	m.Connection = v
}

func (m *MongoTarget) SetSubnetId(v string) {
	m.SubnetId = v
}

func (m *MongoTarget) SetSecurityGroups(v []string) {
	m.SecurityGroups = v
}

func (m *MongoTarget) SetDatabase(v string) {
	m.Database = v
}

func (m *MongoTarget) SetCleanupPolicy(v CleanupPolicy) {
	m.CleanupPolicy = v
}
