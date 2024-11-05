package zksec_gkr

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	//"github.com/stretchr/testify/assert"
)

func TestProveAndVerify(t *testing.T) {
	circuit := Circuit{
		// fixed
		AliceBalance: aliceBalance,
		// fixed
		BobBalance: bobBalance,
		// given by the user
		NewBobBalance: 100000,
		// given by the user
		NewAliceBalance: 0,
		// private
		Transfer: 100000,
	}

	// // compile the circuit
	// ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	// if err != nil {
	// 	t.Fatalf("failed to compile circuit: %v", err)
	// }

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	// pk, _, err := groth16.Setup(ccs)
	// if err != nil {
	// 	t.Fatalf("failed to setup circuit: %v", err)
	// }

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("error occured ", err)
	}

	// create a proof
	proof, err := groth16.Prove(
		oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)),
	)
	if err != nil {
		t.Fatal(err)
	}

	// serialize proof verify
	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	proofHex := hex.EncodeToString(buf.Bytes())
	err = VerifyProof("100000", proofHex)
	if err != nil {
		t.Fatal(err)
	}

	//uploadProof(proofHex, "100000")
	//assert.Equal(t, 1,2)
}

func uploadProof(proof, new_bob_balance string) {
	url := "http://147.182.233.80:8080/"
	
	// Create a map with the data to be sent in JSON format
	data := map[string]string{
		"new_bob_balance": new_bob_balance,
		"proof_hex":       proof,
	}

	// Encode the map into JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
		return
	}


	req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Body:", string(body))
}

