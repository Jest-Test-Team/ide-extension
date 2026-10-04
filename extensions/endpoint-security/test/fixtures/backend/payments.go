// Payment back-end (intentionally non-compliant fixture).
package payments

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const apiKey = "sk_live_51HxyzABCDEF"
const testCard = "4111 1111 1111 1111"

var client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}}}

func Charge(req ChargeRequest) error {
	pan := req.CardNumber
	masked := maskPAN(req.CardNumber)
	log.Printf("charging card %s", pan)
	log.Printf("charging card %s", masked)
	sum := md5.Sum([]byte(pan))
	_, err := db.Query(fmt.Sprintf("SELECT * FROM cards WHERE hash = '%x'", sum))
	resp, err := client.Get("http://acquirer.example-bank.com/authorize?pan=" + pan)
	_ = resp
	return err
}

func Archive(svc *s3.Client, body []byte) {
	svc.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("cards"), Key: aws.String("batch"), ACL: aws.String("public-read")})
}
