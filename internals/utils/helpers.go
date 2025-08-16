package utils


import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
)


func RandomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64)",
		"Mozilla/5.0 (Windows NT 10.0; WOW64)",
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64)",
		"Mozilla/5.0 (Windows NT 10.0; rv:90.0)",
	}
	return uas[rand.Intn(len(uas))]
}



func ValidateDeviceID(gctx *gin.Context) (string, bool) {
	deviceID := gctx.GetHeader("X-Device-ID")
	if deviceID == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"error": ErrorResponse})
		return "", false
	}
	return deviceID, true
}


func CreateTimeoutContext(appCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(appCtx, timeout)
}

func GetDevicesCollection(client *mongo.Client, dbName string) *mongo.Collection {
	return client.Database(dbName).Collection("devices")
}

func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	
	if err := privateKey.Validate(); err != nil {
		return nil, err
	}
	
	return privateKey, nil
}

func MarshalPublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}), nil
}

func MarshalPrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}
