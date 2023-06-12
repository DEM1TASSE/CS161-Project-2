package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username       string
	SharestructKey []byte

	PrivateKey userlib.PKEDecKey
	PublicKey  userlib.PKEEncKey

	DSKey       userlib.DSSignKey
	DSVerifyKey userlib.DSVerifyKey
}

type FileShare struct {
	TreeNodeAddr userlib.UUID
	Key          []byte
	HMACKey      []byte
}

type TreeNode struct {
	MetadataAddr userlib.UUID
	Key          []byte
	HMACKey      []byte

	ShareAddr userlib.UUID
	Owner     string

	Root     userlib.UUID
	Parent   userlib.UUID
	Children []userlib.UUID
}

type FileMetaData struct {
	StartAddress userlib.UUID
	NextAddress  userlib.UUID
	HMACKey      []byte
	FileEncKey   []byte
}

type FileNode struct {
	FileContent []byte
	Next        userlib.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//Check username empty or exist
	if len(username) == 0 {
		return nil, errors.New("Username shouldn't be empty.")
	}

	if len(password) == 0 {
		return nil, errors.New("Password shouldn't be empty.")
	}

	//generate uuid
	HashedUsername := userlib.Hash([]byte(username))
	uuid, err := uuid.FromBytes(HashedUsername[:16])

	_, exist := userlib.DatastoreGet(uuid)

	//Check existence
	if exist {
		return nil, errors.New("User already exists.")
	}

	//generate sharestruct key
	ShareKey, err := userlib.HashKDF(userlib.Hash([]byte(password))[:16], []byte("encryption"))
	userdata.SharestructKey = ShareKey[:16]

	//generate private key and public key
	userdata.PublicKey, userdata.PrivateKey, err = userlib.PKEKeyGen()

	//generate signature key
	userdata.DSKey, userdata.DSVerifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	//store public key
	userlib.KeystoreSet(username+"_PK", userdata.PublicKey)
	userlib.KeystoreSet(username+"_Sign", userdata.DSVerifyKey)

	//encrypt user
	UserData, err := json.Marshal(userdata)
	EncKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	IV := userlib.RandomBytes(16)
	UserEnc := userlib.SymEnc(EncKey, IV , UserData)

	HashKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username+password)), 16)
	UserHash, err := userlib.HMACEval(HashKey, UserEnc)

	//store user data
	data := append(UserEnc, UserHash...)
	userlib.DatastoreSet(uuid, data)

	return &userdata, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	HashedUsername := userlib.Hash([]byte(username))
	uuid, err := uuid.FromBytes(HashedUsername[:16])
	UserData, exist := userlib.DatastoreGet(uuid)

	//Check existence
	if !exist {
		return nil, errors.New("User doesn't exist.")
	}

	//Check Integrity
	if len(UserData) < 64 {
		return nil, errors.New("User data length < 64")
	}

	//Verify integrity
	HashCal := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username+password)), 16)
	UserHash, err := userlib.HMACEval(HashCal, UserData[:len(UserData)-64])
	if !userlib.HMACEqual(UserHash, UserData[len(UserData)-64:]) {
		return nil, errors.New("User data no integrity")
	}

	//Unmarshal decrypted data
	EncKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	UserData = userlib.SymDec(EncKey, UserData[:len(UserData)-64])
	err = json.Unmarshal(UserData, &userdata)

	return &userdata, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}


