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

	_ = strings.ToLower("Hello")

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
	Username  string
	SourceKey []byte

	PrivateKey userlib.PKEDecKey
	PublicKey  userlib.PKEEncKey

	DSKey       userlib.DSSignKey
	DSVerifyKey userlib.DSVerifyKey
}

type FileEntry struct {
	FileMetaAddr userlib.UUID
	Status       string //Own or Share or Received

	EncKey  []byte //For file metadata
	HMACKey []byte
}

type FileMetaData struct {
	//Owner and Share Info
	Owner     string
	ShareList userlib.UUID

	//File Info
	FileName     string
	StartAddress userlib.UUID
	NextAddress  userlib.UUID //For Effecient Append

	//Key
	HMACKey    []byte //For file node
	FileEncKey []byte
}

type FileNode struct {
	FileContent []byte
	Next        userlib.UUID
}

type Invitation struct {
	ShareAddr userlib.UUID
	EncKey    []byte
	HMACKey   []byte
}

type ShareEntry struct {
	Sender    string
	Recipient string
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//Check username empty or exist
	if len(username) == 0 {
		return nil, errors.New("InitUser: Username shouldn't be empty.")
	}

	//Password lenth can be 0
	// if len(password) == 0 {
	// 	return nil, errors.New("InitUser: Password shouldn't be empty.")
	// }

	userdata.Username = username

	//Generate uuid
	HashedUsername := userlib.Hash([]byte(username))
	uuid, err := uuid.FromBytes(HashedUsername[:16])

	_, exist := userlib.DatastoreGet(uuid)

	//Check existence
	if exist {
		return nil, errors.New("InitUser: Username already exists.")
	}

	//Generate source key
	userdata.SourceKey = userlib.RandomBytes(16)

	//Generate private key and public key
	userdata.PublicKey, userdata.PrivateKey, err = userlib.PKEKeyGen()

	//Generate signature key
	userdata.DSKey, userdata.DSVerifyKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	//Store public key
	userlib.KeystoreSet(username+"_PK", userdata.PublicKey)
	userlib.KeystoreSet(username+"_Sign", userdata.DSVerifyKey)

	//Encrypt user
	UserData, err := json.Marshal(userdata)
	EncKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	IV := userlib.RandomBytes(16)
	UserEnc := userlib.SymEnc(EncKey, IV, UserData)

	HashKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username+password)), 16)
	UserHash, err := userlib.HMACEval(HashKey, UserEnc)

	//Store user data
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
		return nil, errors.New("GetUser: User doesn't exist.")
	}

	//Check Integrity
	if len(UserData) < 64 {
		return nil, errors.New("GetUser: User data length < 64")
	}

	//Verify integrity
	HashCal := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username+password)), 16)
	UserHash, err := userlib.HMACEval(HashCal, UserData[:len(UserData)-64])
	if !userlib.HMACEqual(UserHash, UserData[len(UserData)-64:]) {
		return nil, errors.New("GetUser: User data has no integrity")
	}

	//Unmarshal decrypted data
	EncKey := userlib.Argon2Key([]byte(password), userlib.Hash([]byte(username)), 16)
	UserData = userlib.SymDec(EncKey, UserData[:len(UserData)-64])
	err = json.Unmarshal(UserData, &userdata)

	return &userdata, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	//Every user have a independent UserFileList

	//Calculate uuid for UserFileList
	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileList"))[:16])
	UserFileList, exist := userlib.DatastoreGet(UserFileListAddr)

	//Calculate user file list EncKey from Source Key
	SymKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListEncKey"))
	SymKey = SymKey[:16]

	//Calculate user file list HMACKey from Source Key
	HMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListHMACKey"))
	HMACKey = HMACKey[:16]

	curFileList := make(map[string]FileEntry)

	//If UserFileList exist, decrypt it
	if exist {
		//Check length
		length := len(UserFileList)
		if length < 64 {
			return errors.New("StoreFile: User File List length < 64")
		}

		//Check Integrity
		FileListEnc := UserFileList[:length-64]

		// FileListHash := UserFileList[length-64:]
		FileListHashCal, err := userlib.HMACEval(HMACKey, FileListEnc)
		if err != nil {
			return err
		}

		if !userlib.HMACEqual(FileListHashCal, UserFileList[length-64:]) {
			return errors.New("StoreFile: User File List has no integrity")
		}

		//Decrypt UserFileList
		userFileListData := userlib.SymDec(SymKey, FileListEnc)
		err = json.Unmarshal(userFileListData, &curFileList)
	}

	var curFileEntry FileEntry
	curFileEntry, exist = curFileList[filename]
	var curFileMeta FileMetaData
	var curFileNode FileNode

	//If filename not exist, create new filenode, filemetadata, file entry
	if !exist {
		//Create file node
		startAddr := uuid.New()
		curFileNode.FileContent = content
		curFileNode.Next = uuid.New()

		//Generate file key
		fileEncKey, err := userlib.HashKDF(userlib.RandomBytes(16), []byte("fileEncKey"))
		fileEncKey = fileEncKey[:16]

		fileHMACKey, err := userlib.HashKDF(userlib.RandomBytes(16), []byte("fileHMACKey"))
		fileHMACKey = fileHMACKey[:16]
		if err != nil {
			return errors.New("StoreFile: Fail to generate file keys")
		}

		//Store file node
		fileNodeData, err := json.Marshal(curFileNode)
		IV := userlib.RandomBytes(16)
		fileNodeEnc := userlib.SymEnc(fileEncKey, IV, fileNodeData)
		fileNodeHMAC, err := userlib.HMACEval(fileHMACKey, fileNodeEnc)
		fileNodeEnc = append(fileNodeEnc, fileNodeHMAC...)
		userlib.DatastoreSet(startAddr, fileNodeEnc)
		// userlib.DebugMsg("startAddr:", startAddr)

		//Create file metadata
		curFileMeta.Owner = userdata.Username
		curFileMeta.FileName = filename
		curFileMeta.FileEncKey = fileEncKey
		curFileMeta.HMACKey = fileHMACKey
		curFileMeta.StartAddress = startAddr
		curFileMeta.NextAddress = curFileNode.Next

		//Metadata keys
		metadataEncKey, err := userlib.HashKDF(userlib.RandomBytes(16), []byte("metadataEncKey"))
		metadataEncKey = metadataEncKey[:16]
		metadataHMACKey, err := userlib.HashKDF(userlib.RandomBytes(16), []byte("metadataHMACKey"))
		metadataHMACKey = metadataHMACKey[:16]
		if err != nil {
			return errors.New("StoreFile: Fail to generate metadata keys")
		}

		//Store Metadata
		metadataBytes, err := json.Marshal(curFileMeta)
		metadataEnc := userlib.SymEnc(metadataEncKey, userlib.RandomBytes(16), metadataBytes)
		metadataHMAC, err := userlib.HMACEval(metadataHMACKey, metadataEnc)
		if err != nil {
			return errors.New("StoreFile: Fail to encrypt Metadata")
		}
		metadataEnc = append(metadataEnc, metadataHMAC...)
		metadataAddr := uuid.New()
		userlib.DatastoreSet(metadataAddr, metadataEnc)

		//Create file entry
		curFileEntry.Status = "Own"
		curFileEntry.EncKey = metadataEncKey
		curFileEntry.HMACKey = metadataHMACKey
		curFileEntry.FileMetaAddr = metadataAddr

		curFileList[filename] = curFileEntry
	} else {
		//Get and decrypt metadata
		curFileMetaAddr := curFileEntry.FileMetaAddr
		curFileMetaEncKey := curFileEntry.EncKey
		curFileMetaHMACKey := curFileEntry.HMACKey

		// Get metadata
		fileMetaEnc, exist := userlib.DatastoreGet(curFileMetaAddr)
		if !exist {
			return errors.New("StoreFile: File metadata not exist")
		}

		// Check metadata integrity
		fileMetaHMAC := fileMetaEnc[len(fileMetaEnc)-64:]
		hmacCal, err := userlib.HMACEval(curFileMetaHMACKey, fileMetaEnc[:len(fileMetaEnc)-64])
		if err != nil || !userlib.HMACEqual(hmacCal, fileMetaHMAC) {
			return errors.New("StoreFile: File metadata no integrity")
		}

		// Decrypt metadata
		fileMetaBytes := userlib.SymDec(curFileMetaEncKey, fileMetaEnc[:len(fileMetaEnc)-64])
		var fileMeta FileMetaData
		err = json.Unmarshal(fileMetaBytes, &fileMeta)
		if err != nil {
			return errors.New("StoreFile: Error unmarshaling file metadata")
		}

		//Delete old file
		curAddr := fileMeta.StartAddress
		for {
			// Load current file node
			fileNodeEnc, exist := userlib.DatastoreGet(curAddr)
			if !exist {
				return errors.New("StoreFile: Old File Node not exist")
			}

			// check file node integrity
			fileNodeHMAC := fileNodeEnc[len(fileNodeEnc)-64:]
			hmacCal, err := userlib.HMACEval(fileMeta.HMACKey, fileNodeEnc[:len(fileNodeEnc)-64])
			if err != nil || !userlib.HMACEqual(hmacCal, fileNodeHMAC) {
				return errors.New("StoreFile: Old File Node no integrity")
			}

			// decrypt node
			fileNodeBytes := userlib.SymDec(fileMeta.FileEncKey, fileNodeEnc[:len(fileNodeEnc)-64])
			var fileNode FileNode
			err = json.Unmarshal(fileNodeBytes, &fileNode)
			if err != nil {
				return errors.New("StoreFile: Error unmarshaling file node")
			}

			//delete current node
			userlib.DatastoreDelete(curAddr)

			if fileNode.Next == fileMeta.NextAddress {
				break
			}

			curAddr = fileNode.Next
		}

		//Create new file and store
		var newFileNode FileNode
		newNodeAddr := uuid.New()
		newNextAddr := uuid.New()

		newFileNode.FileContent = content
		newFileNode.Next = newNextAddr

		fileNodeData, err := json.Marshal(newFileNode)
		IV := userlib.RandomBytes(16)
		fileNodeEnc := userlib.SymEnc(fileMeta.FileEncKey, IV, fileNodeData)
		fileNodeHMAC, err := userlib.HMACEval(fileMeta.HMACKey, fileNodeEnc)
		fileNodeEnc = append(fileNodeEnc, fileNodeHMAC...)
		userlib.DatastoreSet(newNodeAddr, fileNodeEnc)

		//update metadata and store
		fileMeta.StartAddress = newNodeAddr
		fileMeta.NextAddress = newFileNode.Next

		//store metadata
		metadataBytes, err := json.Marshal(fileMeta)
		IV = userlib.RandomBytes(16)
		metadataEnc := userlib.SymEnc(curFileMetaEncKey, IV, metadataBytes)
		metadataHMAC, err := userlib.HMACEval(curFileMetaHMACKey, metadataEnc)
		if err != nil {
			return errors.New("AppendToFile: Fail to encrypt when update metadata")
		}
		metadataEnc = append(metadataEnc, metadataHMAC...)
		userlib.DatastoreSet(curFileMetaAddr, metadataEnc)
	}

	//Store User File List
	fileListBytes, _ := json.Marshal(curFileList)
	IV := userlib.RandomBytes(16)
	FileListEnc := userlib.SymEnc(SymKey, IV, fileListBytes)
	FileListHMAC, err := userlib.HMACEval(HMACKey, FileListEnc)
	fileListBytes = append(FileListEnc, FileListHMAC...)
	userlib.DatastoreSet(UserFileListAddr, fileListBytes)

	return err
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	//Calculate user file list EncKey from Source Key
	SymKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListEncKey"))
	SymKey = SymKey[:16]

	//Calculate user file list HMACKey from Source Key
	HMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListHMACKey"))
	HMACKey = HMACKey[:16]

	//Calculate uuid for UserFileList
	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileList"))[:16])
	UserFileListBytes, exist := userlib.DatastoreGet(UserFileListAddr)

	if !exist {
		return errors.New("AppendToFile: User File List not exist")
	}

	//Check integrity
	userFileListEnc := UserFileListBytes[:len(UserFileListBytes)-64]
	userFileListHMAC := UserFileListBytes[len(UserFileListBytes)-64:]

	HMACCal, _ := userlib.HMACEval(HMACKey, userFileListEnc)
	if !userlib.HMACEqual(HMACCal, userFileListHMAC) {
		return errors.New("AppendToFile: User File List no integrity")
	}

	//Decrypt UserFileList
	UserFileListBytes = userlib.SymDec(SymKey, userFileListEnc)

	curFileList := make(map[string]FileEntry)
	err = json.Unmarshal(UserFileListBytes, &curFileList)
	if err != nil {
		return err
	}

	curFileEntry, exist := curFileList[filename]
	if !exist {
		return errors.New("AppendToFile: File entry not exist")
	}

	curFileMetaAddr := curFileEntry.FileMetaAddr
	curFileMetaEncKey := curFileEntry.EncKey
	curFileMetaHMACKey := curFileEntry.HMACKey

	// Get metadata
	fileMetaEnc, exist := userlib.DatastoreGet(curFileMetaAddr)
	if !exist {
		return errors.New("AppendToFile: File metadata not exist")
	}

	// Check metadata integrity
	fileMetaHMAC := fileMetaEnc[len(fileMetaEnc)-64:]
	hmacCal, err := userlib.HMACEval(curFileMetaHMACKey, fileMetaEnc[:len(fileMetaEnc)-64])
	if err != nil || !userlib.HMACEqual(hmacCal, fileMetaHMAC) {
		return errors.New("AppendToFile: File metadata no integrity")
	}

	// Decrypt metadata
	fileMetaBytes := userlib.SymDec(curFileMetaEncKey, fileMetaEnc[:len(fileMetaEnc)-64])
	var fileMeta FileMetaData
	err = json.Unmarshal(fileMetaBytes, &fileMeta)
	if err != nil {
		return errors.New("LoadFile: Error unmarshaling file metadata")
	}

	// Create new node
	newNode := FileNode{
		FileContent: content,
		Next:        uuid.New(),
	}

	newNodeData, err := json.Marshal(newNode)
	IV := userlib.RandomBytes(16)
	newNodeEnc := userlib.SymEnc(fileMeta.FileEncKey, IV, newNodeData)
	newNodeHMAC, err := userlib.HMACEval(fileMeta.HMACKey, newNodeEnc)
	newNodeEnc = append(newNodeEnc, newNodeHMAC...)
	userlib.DatastoreSet(fileMeta.NextAddress, newNodeEnc)

	// Update FileMeta
	fileMeta.NextAddress = newNode.Next

	// Store metadata
	metadataBytes, err := json.Marshal(fileMeta)
	IV = userlib.RandomBytes(16)
	metadataEnc := userlib.SymEnc(curFileMetaEncKey, IV, metadataBytes)
	metadataHMAC, err := userlib.HMACEval(curFileMetaHMACKey, metadataEnc)
	if err != nil {
		return errors.New("AppendToFile: Fail to encrypt when update metadata")
	}
	metadataEnc = append(metadataEnc, metadataHMAC...)
	userlib.DatastoreSet(curFileMetaAddr, metadataEnc)

	return err
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//Calculate user file list EncKey from Source Key
	SymKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListEncKey"))
	SymKey = SymKey[:16]
	// userlib.DebugMsg("SymKey", SymKey)

	//Calculate user file list HMACKey from Source Key
	HMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListHMACKey"))
	HMACKey = HMACKey[:16]

	//Calculate uuid for UserFileList
	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileList"))[:16])
	UserFileListBytes, exist := userlib.DatastoreGet(UserFileListAddr)

	if !exist {
		return nil, errors.New("LoadFile: User File List not exist")
	}

	//Check integrity
	userFileListEnc := UserFileListBytes[:len(UserFileListBytes)-64]
	userFileListHMAC := UserFileListBytes[len(UserFileListBytes)-64:]

	HMACCal, _ := userlib.HMACEval(HMACKey, userFileListEnc)
	if !userlib.HMACEqual(HMACCal, userFileListHMAC) {
		return nil, errors.New("LoadFile: User File List no integrity")
	}

	//Decrypt UserFileList
	UserFileListBytes = userlib.SymDec(SymKey, userFileListEnc)

	curFileList := make(map[string]FileEntry)
	err = json.Unmarshal(UserFileListBytes, &curFileList)
	if err != nil {
		return nil, err
	}
	// userlib.DebugMsg("curFileList:",curFileList)

	curFileEntry, exist := curFileList[filename]
	// userlib.DebugMsg("curFileEntry:",curFileEntry)
	if !exist {
		userlib.DebugMsg("curFileList:", curFileList)
		return nil, errors.New("LoadFile: File entry not exist")
	}

	curFileMetaAddr := curFileEntry.FileMetaAddr
	curFileMetaEncKey := curFileEntry.EncKey
	curFileMetaHMACKey := curFileEntry.HMACKey

	userlib.DebugMsg("curFileMetaAddr:", curFileMetaAddr)

	// Get metadata
	fileMetaEnc, exist := userlib.DatastoreGet(curFileMetaAddr)
	if !exist {
		return nil, errors.New("LoadFile: File metadata not exist")
	}

	// Check metadata integrity
	fileMetaHMAC := fileMetaEnc[len(fileMetaEnc)-64:]
	hmacCal, err := userlib.HMACEval(curFileMetaHMACKey, fileMetaEnc[:len(fileMetaEnc)-64])
	if err != nil || !userlib.HMACEqual(hmacCal, fileMetaHMAC) {
		return nil, errors.New("LoadFile: File metadata no integrity")
	}

	// Decrypt metadata
	fileMetaBytes := userlib.SymDec(curFileMetaEncKey, fileMetaEnc[:len(fileMetaEnc)-64])
	var fileMeta FileMetaData
	err = json.Unmarshal(fileMetaBytes, &fileMeta)
	if err != nil {
		return nil, errors.New("LoadFile: Error unmarshaling file metadata")
	}

	// Load File Content
	curAddr := fileMeta.StartAddress

	for {
		// Load current file node
		fileNodeEnc, exist := userlib.DatastoreGet(curAddr)
		if !exist {
			return nil, errors.New("LoadFile: File node not exist")
		}

		// check file node integrity
		fileNodeHMAC := fileNodeEnc[len(fileNodeEnc)-64:]
		hmacCal, err := userlib.HMACEval(fileMeta.HMACKey, fileNodeEnc[:len(fileNodeEnc)-64])
		if err != nil || !userlib.HMACEqual(hmacCal, fileNodeHMAC) {
			return nil, errors.New("LoadFile: File Node no integrity")
		}

		// decrypt node
		fileNodeBytes := userlib.SymDec(fileMeta.FileEncKey, fileNodeEnc[:len(fileNodeEnc)-64])
		var fileNode FileNode
		err = json.Unmarshal(fileNodeBytes, &fileNode)
		if err != nil {
			return nil, errors.New("LoadFile: Error unmarshaling file node")
		}

		// append node content
		content = append(content, fileNode.FileContent...)

		if fileNode.Next == fileMeta.NextAddress {
			break
		}

		curAddr = fileNode.Next
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	/*
		1. Read FileEntry - Get file metadata
		2. Verify metadata integrity
		3. Generate FileEntryCopy for share and store
		4. Generate invitation with pointer to FileEntryCopy
		5. Store invitation
	*/

	//1. Check recipient validity
	_, ok := userlib.KeystoreGet(recipientUsername + "_PK")
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: Recipient not valid")
	}

	//2. Get User File List
	SymKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListEncKey"))
	SymKey = SymKey[:16]
	HMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListHMACKey"))
	HMACKey = HMACKey[:16]

	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileList"))[:16])
	UserFileListBytes, exist := userlib.DatastoreGet(UserFileListAddr)

	if !exist {
		return uuid.Nil, errors.New("CreateInvitation: User File List not exist")
	}

	//Check integrity
	userFileListEnc := UserFileListBytes[:len(UserFileListBytes)-64]
	userFileListHMAC := UserFileListBytes[len(UserFileListBytes)-64:]

	HMACCal, _ := userlib.HMACEval(HMACKey, userFileListEnc)
	if !userlib.HMACEqual(HMACCal, userFileListHMAC) {
		return uuid.Nil, errors.New("CreateInvitation: User File List no integrity")
	}

	//Decrypt UserFileList
	UserFileListBytes = userlib.SymDec(SymKey, userFileListEnc)

	curFileList := make(map[string]FileEntry)
	err = json.Unmarshal(UserFileListBytes, &curFileList)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error unmarshaling UserFileList")
	}

	curFileEntry, exist := curFileList[filename]
	if !exist {
		return uuid.Nil, errors.New("CreateInvitation: File entry not exist")
	}

	//3. Check metadata and filenode integrity
	curFileMetaAddr := curFileEntry.FileMetaAddr
	curFileMetaEncKey := curFileEntry.EncKey
	curFileMetaHMACKey := curFileEntry.HMACKey

	// Get metadata
	fileMetaEnc, exist := userlib.DatastoreGet(curFileMetaAddr)
	if !exist {
		return uuid.Nil, errors.New("CreateInvitation: File metadata not exist")
	}

	// Check metadata integrity
	fileMetaHMAC := fileMetaEnc[len(fileMetaEnc)-64:]
	hmacCal, err := userlib.HMACEval(curFileMetaHMACKey, fileMetaEnc[:len(fileMetaEnc)-64])
	if err != nil || !userlib.HMACEqual(hmacCal, fileMetaHMAC) {
		return uuid.Nil, errors.New("CreateInvitation: File metadata no integrity")
	}

	//4. Generate FileEntry copy for invitation
	FileEntryCopy := FileEntry{
		FileMetaAddr: curFileMetaAddr,
		Status:       "Share",
		HMACKey:      curFileMetaHMACKey,
		EncKey:       curFileMetaEncKey,
	}

	// Store FileEntryCopy
	ShareSymKey := userlib.RandomBytes(16)
	ShareHMACKey := userlib.RandomBytes(16)

	fileEntryCopyData, err := json.Marshal(FileEntryCopy)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error marshaling FileEntryCopy")
	}
	fileEntryCopyEnc := userlib.SymEnc(ShareSymKey, userlib.RandomBytes(16), fileEntryCopyData)
	fileEntryCopyHMAC, err := userlib.HMACEval(ShareHMACKey, fileEntryCopyEnc)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error generating HMAC for FileEntryCopy")
	}
	fileEntryCopyEnc = append(fileEntryCopyEnc, fileEntryCopyHMAC...)
	fileEntryCopyAddr := uuid.New()
	userlib.DatastoreSet(fileEntryCopyAddr, fileEntryCopyEnc)

	//5. Generate and store invitation
	invitation := Invitation{
		ShareAddr: fileEntryCopyAddr,
		EncKey:    ShareSymKey,
		HMACKey:   ShareHMACKey,
	}
	recipientPK, _ := userlib.KeystoreGet(recipientUsername + "_PK")
	senderSK := userdata.DSKey
	invitationData, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error marshaling invitation")
	}
	// userlib.DebugMsg("Invitation data size:%v", len(invitationData))
	invitationEnc, err := userlib.PKEEnc(recipientPK, invitationData)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Error encrypting invitation")
	}
	invitationSign, err := userlib.DSSign(senderSK, invitationEnc)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Store invitation failed")
	}
	userlib.DatastoreSet(invitationPtr, append(invitationEnc, invitationSign...))

	return invitationPtr, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	/*
		1. Check sender validity
		2. Get invitation and check integrity
		3. Get FileEntryCopy and check integrity
		4. Get UserFileList
		5. Add NewFileEntry to UserFileList
		6. Delete invitation
		7. Update ShareList
		8. Store UserFileList
	*/

	//1. Check sender validity
	senderSK, ok := userlib.KeystoreGet(senderUsername + "_Sign")
	if !ok {
		return errors.New("AcceptInvitation: Sender not valid")
	}

	//2. Get invitation and check integrity
	invitationEnc, exist := userlib.DatastoreGet(invitationPtr)
	if !exist {
		return errors.New("AcceptInvitation: Invitation not exist")
	}
	if len(invitationEnc) < 256 {
		return errors.New("AcceptInvitation: Invitation has been tampered")
	}
	// Check signature
	invitationSign := invitationEnc[len(invitationEnc)-256:]
	invitationEnc = invitationEnc[:len(invitationEnc)-256]
	err := userlib.DSVerify(senderSK, invitationEnc, invitationSign)
	if err != nil {
		return errors.New("AcceptInvitation: Invitation signature verification failed")
	}
	// Decrypt invitation
	invitationData, err := userlib.PKEDec(userdata.PrivateKey, invitationEnc)
	if err != nil {
		return errors.New("AcceptInvitation: Integrity compromised")
	}
	var curInvitation Invitation
	err = json.Unmarshal(invitationData, &curInvitation)
	if err != nil {
		return errors.New("AcceptInvitation: Error unmarshaling invitation")
	}

	//3. Get FileEntryCopy and check integrity
	curFileCopyAddr := curInvitation.ShareAddr
	curFileCopyEncKey := curInvitation.EncKey
	curFileCopyHMACKey := curInvitation.HMACKey

	curFileCopyEnc, exist := userlib.DatastoreGet(curFileCopyAddr)
	if !exist {
		return errors.New("AcceptInvitation: FileEntryCopy not exist")
	}

	curFileCopyHMAC := curFileCopyEnc[len(curFileCopyEnc)-64:]
	hmacCal, err := userlib.HMACEval(curFileCopyHMACKey, curFileCopyEnc[:len(curFileCopyEnc)-64])
	if err != nil || !userlib.HMACEqual(hmacCal, curFileCopyHMAC) {
		return errors.New("AcceptInvitation: FileEntryCopy no integrity")
	}

	curFileCopy := userlib.SymDec(curFileCopyEncKey, curFileCopyEnc[:len(curFileCopyEnc)-64])
	var newFileEntry FileEntry
	err = json.Unmarshal(curFileCopy, &newFileEntry)
	if err != nil {
		return errors.New("AcceptInvitation: Error unmarshaling FileEntryCopy")
	}

	//4. Get UserFileList
	SymKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListEncKey"))
	SymKey = SymKey[:16]
	HMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("UserFileListHMACKey"))
	HMACKey = HMACKey[:16]

	UserFileListAddr, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + "UserFileList"))[:16])
	UserFileListBytes, exist := userlib.DatastoreGet(UserFileListAddr)
	userlib.DebugMsg("UserFileListBytes: %v", UserFileListBytes)
	curFileList := make(map[string]FileEntry)
	if exist {
		// Check integrity
		userFileListEnc := UserFileListBytes[:len(UserFileListBytes)-64]
		userFileListHMAC := UserFileListBytes[len(UserFileListBytes)-64:]

		HMACCal, _ := userlib.HMACEval(HMACKey, userFileListEnc)
		if !userlib.HMACEqual(HMACCal, userFileListHMAC) {
			return errors.New("AcceptInvitation: User File List no integrity")
		}

		// Decrypt UserFileList
		UserFileListBytes = userlib.SymDec(SymKey, userFileListEnc)
		err = json.Unmarshal(UserFileListBytes, &curFileList)
		if err != nil {
			return errors.New("Accept: Error unmarshaling UserFileList")
		}
	}

	//5. Add FileEntryCopy to UserFileList
	_, exist = curFileList[filename]
	if exist {
		return errors.New("AcceptInvitation: File already exist")
	} else {
		newFileEntry.Status = "received"
		curFileList[filename] = newFileEntry
	}

	//6. Delete invitation info
	userlib.DatastoreDelete(invitationPtr)
	userlib.DatastoreDelete(curFileCopyAddr)

	//7. Update Share List

	//8. Store UserFileList
	fileListBytes, _ := json.Marshal(curFileList)
	IV := userlib.RandomBytes(16)
	FileListEnc := userlib.SymEnc(SymKey, IV, fileListBytes)
	FileListHMAC, err := userlib.HMACEval(HMACKey, FileListEnc)
	fileListBytes = append(FileListEnc, FileListHMAC...)
	userlib.DatastoreSet(UserFileListAddr, fileListBytes)

	return err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
