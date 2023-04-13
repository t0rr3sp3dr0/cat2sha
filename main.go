package main

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"

	"golang.org/x/text/encoding/unicode"
)

const (
	binaryMarker             = '*'
	cnvNameFilename          = "Filename"
	oidPKCS7SignedData       = "1.2.840.113549.1.7.2"
	oidMSSpcIndirectData     = "1.3.6.1.4.1.311.2.1.4"
	oidMSCabData             = "1.3.6.1.4.1.311.2.1.25"
	oidMSCertTrustList       = "1.3.6.1.4.1.311.10.1"
	oidMSCatalogList         = "1.3.6.1.4.1.311.12.1.1"
	oidMSCatalogListMember   = "1.3.6.1.4.1.311.12.1.2"
	oidMSCatalogListMemberV2 = "1.3.6.1.4.1.311.12.1.3"
	oidMSCatalogNameValue    = "1.3.6.1.4.1.311.12.2.1"
	oidMSCatalogMemberInfo   = "1.3.6.1.4.1.311.12.2.2"
	oidMSCatalogMemberInfo2  = "1.3.6.1.4.1.311.12.2.3"
	oidSHA1                  = "1.3.14.3.2.26"
	oidSHA256                = "2.16.840.1.101.3.4.2.1"
)

var (
	utf16Decoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type signedData struct {
	Version          asn1.RawValue
	DigestAlgorithms asn1.RawValue
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"tag:0,implicit,optional"`
	Crls             asn1.RawValue `asn1:"tag:1,implicit,optional"`
	SignerInfos      asn1.RawValue
}

type certTrustList struct {
	CatalogListVersion  asn1.RawValue
	UnknownString       asn1.RawValue
	TrustUtcTime        asn1.RawValue
	CatalogListMemberId asn1.RawValue
	Members             []catalogListMember
	Attributes          []asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type catalogListMember struct {
	Data       asn1.RawValue
	Attributes []memberAttribute `asn1:"optional,set"`
}

type memberAttribute struct {
	Oid     asn1.ObjectIdentifier
	Content []asn1.RawValue `asn1:"set"`
}

func (ma *memberAttribute) MemberAttributeContents() []memberAttributeContent {
	var ptr interface{}
	switch oid := ma.Oid.String(); oid {
	case oidMSCatalogNameValue:
		ptr = &catalogNameValue{}

	case oidMSCatalogMemberInfo:
		return nil

	case oidMSCatalogMemberInfo2:
		return nil

	case oidMSSpcIndirectData:
		ptr = &spcIndirectData{}

	default:
		log.Panicf("%v defaulted", oid)
	}

	var macs []memberAttributeContent
	for _, content := range ma.Content {
		if _, err := asn1.Unmarshal(content.FullBytes, ptr); err != nil {
			log.Panic(err)
		}

		mac := reflect.ValueOf(ptr).Elem().Interface()
		macs = append(macs, mac)
	}

	return macs
}

type memberAttributeContent interface{}

type catalogNameValue struct {
	Name  string
	Flags asn1.RawValue
	Value []byte
}

type spcIndirectData struct {
	Data          algorithmIdentifier
	MessageDigest digestInfo
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type digestInfo struct {
	DigestAlgorithm algorithmIdentifier
	Digest          []byte
}

func main() {
	bytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Panic(err)
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(bytes, &ci); err != nil {
		log.Panic(err)
	}
	if contentType := ci.ContentType.String(); contentType != oidPKCS7SignedData {
		log.Panicf("%v != oidPKCS7SignedData", contentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		log.Panic(err)
	}
	if contentType := sd.ContentInfo.ContentType.String(); contentType != oidMSCertTrustList {
		log.Panicf("%v != oidMSCertTrustList", contentType)
	}

	var ctl certTrustList
	if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &ctl); err != nil {
		log.Panic(err)
	}

	for _, member := range ctl.Members {
		var macses []memberAttributeContent
		for _, attr := range member.Attributes {
			macs := attr.MemberAttributeContents()
			macses = append(macses, macs...)
		}

		var cnv *catalogNameValue
		var sid *spcIndirectData
		for _, mac := range macses {
			switch mac := mac.(type) {
			case catalogNameValue:
				if mac.Name != cnvNameFilename {
					continue
				}
				cnv = &mac

			case spcIndirectData:
				if oid := mac.Data.Algorithm.String(); oid != oidMSCabData {
					continue
				}
				if oid := mac.MessageDigest.DigestAlgorithm.Algorithm.String(); oid != oidSHA1 && oid != oidSHA256 {
					continue
				}
				sid = &mac
			}
		}

		if cnv == nil || sid == nil {
			continue
		}

		name, err := utf16Decoder.Bytes(cnv.Value)
		if err != nil {
			log.Panic(err)
		}

		hash := hex.EncodeToString(sid.MessageDigest.Digest)

		fmt.Printf("%s %c%s\n", hash, binaryMarker, name)
	}
}
