package main

import (
	"fmt"
	//"encoding/json"
	
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/core/chaincode/shim/ext/entities"
	"github.com/hyperledger/fabric/protos/peer"
)

const DECKEY = "DECKEY"
const ENCKEY = "ENCKEY"
const IV = "IV"

// SimpleAsset implements a simple chaincode to manage an asset
type SimpleAsset struct {
	bccspInst bccsp.BCCSP
}


// Init is called during chaincode instantiation to initialize any data.
func (t *SimpleAsset) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

// Invoke is called per transaction on the chaincode. Each transaction is
// either a 'get' or a 'set' on the asset created by Init function. The 'set'
// method may create a new asset by specifying a new key-value pair.
func (t *SimpleAsset) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// Extract the function and args from the transaction proposal
    fn, args := stub.GetFunctionAndParameters()
	
	var result string
    var err error
    if fn == "addRecord" {
        result, err = addRecord(stub, args)
    } else if fn == "getRecord" {
        result, err = getRecord(stub, args)
    } else if fn == "encRecord" {
		tMap, err := stub.GetTransient()
		if err != nil {
			return shim.Error(fmt.Sprintf("Could not retrieve transient, err %s", err))
		}
		result, err = t.encRecord(stub, args, tMap[ENCKEY], tMap[IV])
	} else {
		tMap, err := stub.GetTransient()
		if err != nil {
			return shim.Error(fmt.Sprintf("Could not retrieve transient, err %s", err))
		}
		result, err = t.decRecord(stub, args, tMap[DECKEY], tMap[IV])
	}
    if err != nil {
            return shim.Error(err.Error())
    }

    // Return the result as success payload
    return shim.Success([]byte(result))
}

// encRecord exposes how to write state to the ledger after having
// encrypted it with an AES 256 bit key that has been provided to the chaincode through the
// transient field
func (t *SimpleAsset) encRecord(stub shim.ChaincodeStubInterface, args []string, encKey, IV []byte) (string, error) {
	// create the encrypter entity - we give it an ID, the bccsp instance, the key and (optionally) the IV
	ent, err := entities.NewAES256EncrypterEntity("ID", t.bccspInst, encKey, IV)
	if err != nil {
		return "", err
	}

	if len(args) != 4 {
		return "",fmt.Errorf("Expected 4 parameters to function Encrypter")
	}
	
	key := args[0] + args[1]
	cleartextValue := []byte(args[2])
	
	// here, we encrypt cleartextValue and assign it to key
	err = encryptAndPutState(stub, ent, key, cleartextValue)
	if err != nil {
		return "", err
	}
	return "key:" + key + " cleartextValue:" + string(cleartextValue),nil

}

// Decrypter exposes how to read from the ledger and decrypt using an AES 256
// bit key that has been provided to the chaincode through the transient field.
func (t *SimpleAsset) decRecord(stub shim.ChaincodeStubInterface, args []string, decKey, IV []byte) (string, error) {
	// create the encrypter entity - we give it an ID, the bccsp instance, the key and (optionally) the IV
	ent, err := entities.NewAES256EncrypterEntity("ID", t.bccspInst, decKey, IV)
	if err != nil {
		return "", err
	}

	if len(args) != 2 {
		return "",fmt.Errorf("Expected 2 parameters to function Decrypter")
	}

	key := args[0] + args[1]
	
	// here we decrypt the state associated to key
	cleartextValue, err := getStateAndDecrypt(stub, ent, key)
	if err != nil {
		return "",err
	}

	// here we return the decrypted value as a result
	return string(cleartextValue),nil
}

// encryptAndPutState encrypts the supplied value using the
// supplied entity and puts it to the ledger associated to
// the supplied KVS key
func encryptAndPutState(stub shim.ChaincodeStubInterface, ent entities.Encrypter, key string, value []byte) error {
	// at first we use the supplied entity to encrypt the value
	ciphertext, err := ent.Encrypt(value)
	if err != nil {
		return err
	}

	return stub.PutState(key, ciphertext)
}

// getStateAndDecrypt retrieves the value associated to key,
// decrypts it with the supplied entity and returns the result
// of the decryption
func getStateAndDecrypt(stub shim.ChaincodeStubInterface, ent entities.Encrypter, key string) ([]byte, error) {
	// at first we retrieve the ciphertext from the ledger
	ciphertext, err := stub.GetState(key)
	if err != nil {
		return nil, err
	}

	// GetState will return a nil slice if the key does not exist.
	// Note that the chaincode logic may want to distinguish between
	// nil slice (key doesn't exist in state db) and empty slice
	// (key found in state db but value is empty). We do not
	// distinguish the case here
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("no ciphertext to decrypt")
	}

	return ent.Decrypt(ciphertext)
}

func addRecord(stub shim.ChaincodeStubInterface, args []string)(string, error) {
	if len(args) != 4 {
            return "", fmt.Errorf("Incorrect arguments. Expecting 4 arguments")
    }
	err := stub.PutState(args[0] + args[1], []byte(args[2]))
    if err != nil {
            return "", fmt.Errorf("Failed to set asset: %s", args[0])
    }
    return args[2], nil
}

func getRecord(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if len(args) != 2 {
            return "", fmt.Errorf("Incorrect arguments. Expecting 2 arguments")
    }
	value, err := stub.GetState(args[0] + args[1])
    if err != nil {
            return "", fmt.Errorf("Failed to get asset: %s with error: %s", args[0], err)
    }
    if value == nil {
            return "", fmt.Errorf("Asset not found: %s", args[0])
    }
    return string(value), nil
}

// main function starts up the chaincode in the container during instantiate
func main() {
	factory.InitFactories(nil)
	
    if err := shim.Start(&SimpleAsset{factory.GetDefault()}); err != nil {
            fmt.Printf("Error starting SimpleAsset chaincode: %s", err)
    }
}