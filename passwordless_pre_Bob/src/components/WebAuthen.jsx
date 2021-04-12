import React, { Component } from "react";
class WebAuthen extends Component {
  constructor(props) {
    super(props);
    this.state = {
      // we assume Bob's public key via eciespy as did_Bob
      did_Bob:
        "0x7fb36db75a49cc7b14011d1b88623749f33da2aa45b328aa4854337a0c0e7656241f14d56e2e91f8cbbc4d6fdc2cf3462bcfa1f14f79d537c3e58380f204c730",
      // sk_me_Bob: Bob's secret key from eciespy
      sk_me_Bob:
        "0xc1f3721a60df95b19f079a794eec9555f2afc2fe428df94fe5308bb4a5efad5a",
      // pkey_server_Bob: public key of Bob's cloud wallet
      pkey_server_Bob:
        "0xeb608b4d1002c74dd55636b70617bff5f13b4cf548c22fc224798a05cbb688036488a86d32118efd5f5cacc75996009b73f3fe214b15ada419da1c700e577f78",
      // private key for Bob to sign digital signature
      private_sign_Bob:
        "62542187512261159204913937044612363382356928282649244457036375298228417908947",
      // secret key for Bob to use with Umbral
      sk_umbral_Bob: "0x000002C84AE01688",
      // public key for Bob to use with Umbral
      pk_umbral_Bob: "A8flUB3VhASzvTbthAuTjE++zclLkYji6Xho/aaHgzWc",
      // public key for Alice to use with Umbral
      pk_umbral_Alice: "AzMHeCds/PHJaX4BO3PqGa+qzJi1tR0x15ABL4snQ3MT",
      //value is just for storing the value after local wallet retrieves Bob's own resource from cloud wallet
      value: "Nothing",
      // encrypted Bob's did
      en_did_Bob: "default",
      // encrypted Bob's key_r for digital signature
      en_key_r_Bob: "default_r",
      // encrypted Bob's key_s for digital signature
      en_key_s_Bob: "default_s",
      // token for accessing Bob's cloud wallet
      token: "No token",
      // connection status to cloud wallet
      connect: "Not connected",
      // decrypted text from the one that Alice's cloud wallet sent to Bob's cloud wallet
      AliceText: "No Alice's Text",
    };
  }
  // for requesting to connect with its own (Bob's cloud wallet)
  connectCloud = () => {
    // sign Bob's did
    fetch("http://127.0.0.1:7777/ecdsa/sign", {
      method: "post",
      body: JSON.stringify({
        private_sign: this.state.private_sign_Bob,
        data: this.state.did_Bob,
      }),
    })
      .then((resp) => resp.json())
      .then((keypair) => {
        // encrypt Bob's did with eciespy
        fetch("http://127.0.0.1:7777/eciespy/encrypt", {
          method: "POST",
          body: JSON.stringify({
            pk_hex: this.state.pkey_server_Bob,
            data: this.state.did_Bob,
          }),
        })
          .then((r) => r.json())
          .then((r) => {
            this.setState({ en_did_Bob: r.encrypted });
            // encrypt Bob's key_r with eciespy
            fetch("http://127.0.0.1:7777/eciespy/encrypt", {
              method: "POST",
              body: JSON.stringify({
                pk_hex: this.state.pkey_server_Bob,
                data: keypair["key_r"].toString(),
              }),
            })
              .then((r) => r.json())
              .then((r) => {
                this.setState({ en_key_r_Bob: r.encrypted });
                // encrypt Bob's key_s with eciespy
                fetch("http://127.0.0.1:7777/eciespy/encrypt", {
                  method: "POST",
                  body: JSON.stringify({
                    pk_hex: this.state.pkey_server_Bob,
                    data: keypair["key_s"].toString(),
                  }),
                })
                  .then((r) => r.json())
                  .then((r) => {
                    this.setState({ en_key_s_Bob: r.encrypted });
                    // request token to Bob's cloud wallet by sending encrypted did, key_r, key_s
                    fetch("http://127.0.0.1:5555/apibob/requesttoken", {
                      method: "POST",
                      body: JSON.stringify({
                        key_r: this.state.en_key_r_Bob,
                        key_s: this.state.en_key_s_Bob,
                        username: this.state.en_did_Bob,
                      }),
                    })
                      .then((respon) => respon.json())
                      .then((r) => {
                        // decrypt the encrypted token received from cloud wallet (if it passes the authentication and cloud wallet sent token back)
                        fetch("http://127.0.0.1:7777/eciespy/decrypt", {
                          method: "POST",
                          body: JSON.stringify({
                            sk_hex: this.state.sk_me_Bob,
                            data: r.token,
                          }),
                        })
                          .then((respon) => respon.json())
                          .then((r) => {
                            console.log("TOKEN JYAA");
                            console.log(r.decrypted);
                            this.setState({ token: r.decrypted });
                            let header = new Headers();
                            // request access to cloud wallet with decrypted token
                            header.set(
                              "Authorization",
                              "Basic " +
                                btoa(this.state.token + ":" + "anything")
                            );
                            fetch("http://127.0.0.1:5555/apibob/connected", {
                              method: "GET",
                              headers: header,
                            })
                              .then((respon) => respon.json())
                              .then((r) => this.setState({ connect: r.data }));
                          });
                      });
                  });
              });
          });
      });
  };
  // retrieve Bob's encrypted data from cloud wallet
  getResource = () => {
    let header2 = new Headers();
    // request Bob's resource with the token (get encrypted resource back if the token is authorized)
    header2.set(
      "Authorization",
      "Basic " + btoa(this.state.token + ":" + "anything")
    );
    fetch("http://127.0.0.1:5555/apibob/resource", {
      method: "GET",
      headers: header2,
    })
      .then((respon) => respon.json())
      .then((r) => {
        // decrypt the received encrypted data
        fetch("http://127.0.0.1:8000/umbral/decrypt", {
          method: "POST",
          body: JSON.stringify({
            sk_hex: this.state.sk_umbral_Bob,
            cipher_text: r.data,
            capsule_text: r.capsule,
          }),
        })
          .then((respon) => respon.json())
          .then((re) => this.setState({ value: re.decrypted }));
      });
  };
  // retrieve the Alice's resource encrypted with Alice's key and corresponding necessary material from cloud wallet to decrypt in local wallet
  getAliceResource = () => {
    let header3 = new Headers();
    // get Alice's encrypted resource with necessary materials for umbral to decrypt in Bob's local wallet
    header3.set(
      "Authorization",
      "Basic " + btoa(this.state.token + ":" + "anything")
    );
    fetch("http://127.0.0.1:5555/apibob/getAliceData", {
      method: "GET",
      headers: header3,
    })
      .then((respon) => respon.json())
      .then((r) => {
        // decrypt Alice's resource by umbral
        fetch("http://127.0.0.1:8000/umbral/decrypt_pre", {
          method: "POST",
          body: JSON.stringify({
            ciphertext: r.ciphertext,
            capsule: r.capsule,
            k_frag: r.k_frag,
            verifying_alice: r.verifying_alice,
            pk_umbral_Alice_string: this.state.pk_umbral_Alice,
            pk_umbral_Bob_string: this.state.pk_umbral_Bob,
            sk_umbral_Bob_string: this.state.sk_umbral_Bob,
          }),
        })
          .then((respon) => respon.json())
          .then((re) => this.setState({ AliceText: re.cleartext }));
      });
  };
  // delete the Alice's resource encrypted with Alice's key and components for using with Umbral, delete from the cloud wallet
  deleteAliceResource = () => {
    let header4 = new Headers();
    header4.set(
      "Authorization",
      "Basic " + btoa(this.state.token + ":" + "anything")
    );
    fetch("http://127.0.0.1:5555/apibob/deleteAliceData", {
      method: "GET",
      headers: header4,
    }).then(this.setState({ AliceText: "No Alice's Text" }));
  };
  render() {
    return (
      <div>
        <h1 style={{ color: "blue" }}>Bob's Local wallet</h1>
        <button onClick={() => this.connectCloud()}>
          Connect Cloud Wallet
        </button>
        {/* show the status whether Alice is connected to her own cloud wallet or not */}
        <h1>{this.state.connect}</h1>
        <button onClick={() => this.getResource()}>Get Bob's own data</button>
        {/* show the value of Alice's own resource (that is encrypted in her cloud wallet) */}
        <h1>{this.state.value}</h1>
        <button onClick={() => this.getAliceResource()}>
          Get Alice's data
        </button>
        {/* show the value of Alice's data that Alice sent to Bob */}
        <h1>{this.state.AliceText}</h1>
        <button onClick={() => this.deleteAliceResource()}>
          Delete Alice's data
        </button>
      </div>
    );
  }
}
export default WebAuthen;
