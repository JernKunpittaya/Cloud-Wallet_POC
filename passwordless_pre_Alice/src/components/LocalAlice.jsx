import React, { Component } from "react";
class LocalAlice extends Component {
  constructor(props) {
    super(props);
    this.state = {
      // we assume Alice's public key via eciespy as did_Alice
      did_Alice:
        "0xc962736683a565d12dbc299b5a17d97fe53137af2a151766c741d5fbb1d1a873594c648f28702a01b7588d895c56763859e52d31c62abf9deb15659b497c9928",
      // sk_me_Alice: Alice's secret key from eciespy
      sk_me_Alice:
        "0xa4207fcf1f7457b55a781873de7a2715a363bbea87f387b40b3c9dfaae63f7f9",
      // pkey_server_Alice: public key of Alice's cloud wallet
      pkey_server_Alice:
        "0x9d251415240aca8d926596bfe945fde874f4e4444709db76173d2a439cba30da0de1663c7709d8c399adb05a044eafc49aa1ab35f827fe32e7dd2d98a9d6cc34",
      // private key for Alice to sign digital signature
      private_sign_Alice:
        "55296113075965769983214099068001948551333506148419620277267301735931301306895",
      // secret key for Alice to use with Umbral
      sk_umbral_Alice: "0x000001F6F133A748",
      // public key for Bob to use with Umbral
      pk_umbral_Bob: "A8flUB3VhASzvTbthAuTjE++zclLkYji6Xho/aaHgzWc",
      //value is just for storing the value after local wallet retrieves Alice's own resource from cloud wallet
      value: "Nothing",
      // encrypted Alice's did
      en_did_Alice: "default",
      // encrypted Alice's key_r for digital signature
      en_key_r_Alice: "default_r",
      // encrypted Alice's key_s for digital signature
      en_key_s_Alice: "default_s",
      // token for accessing Alice's cloud wallet
      token: "No token",
      // connection status to cloud wallet
      connect: "Not connected to cloud",
      // status whether Alice sent data to Bob yet
      bobstatus: "Not sent to Bob",
      // verifying string to use with Umbral
      verifying_string_Alice: "Nope",
      // kfrag string to use with Umbral
      kfrag_string: "None",
    };
  }
  // for requesting to connect with its own (Alice's cloud wallet)
  connectCloud = () => {
    // sign Alice's did
    fetch("http://127.0.0.1:7777/ecdsa/sign", {
      method: "post",
      body: JSON.stringify({
        private_sign: this.state.private_sign_Alice,
        data: this.state.did_Alice,
      }),
    })
      .then((resp) => resp.json())
      .then((keypair) => {
        // encrypt Alice's did with eciespy
        fetch("http://127.0.0.1:7777/eciespy/encrypt", {
          method: "POST",
          body: JSON.stringify({
            pk_hex: this.state.pkey_server_Alice,
            data: this.state.did_Alice,
          }),
        })
          .then((r) => r.json())
          .then((r) => {
            this.setState({ en_did_Alice: r.encrypted });
            // encrypt Alice's key_r with eciespy
            fetch("http://127.0.0.1:7777/eciespy/encrypt", {
              method: "POST",
              body: JSON.stringify({
                pk_hex: this.state.pkey_server_Alice,
                data: keypair["key_r"].toString(),
              }),
            })
              .then((r) => r.json())
              .then((r) => {
                this.setState({ en_key_r_Alice: r.encrypted });
                // encrypt Alice's key_s with eciespy
                fetch("http://127.0.0.1:7777/eciespy/encrypt", {
                  method: "POST",
                  body: JSON.stringify({
                    pk_hex: this.state.pkey_server_Alice,
                    data: keypair["key_s"].toString(),
                  }),
                })
                  .then((r) => r.json())
                  .then((r) => {
                    this.setState({ en_key_s_Alice: r.encrypted });
                    // request token to Alice's cloud wallet by sending encrypted did, key_r, key_s
                    fetch("http://127.0.0.1:5000/api/requesttoken", {
                      method: "POST",
                      body: JSON.stringify({
                        key_r: this.state.en_key_r_Alice,
                        key_s: this.state.en_key_s_Alice,
                        username: this.state.en_did_Alice,
                      }),
                    })
                      .then((respon) => respon.json())
                      .then((r) => {
                        // decrypt the encrypted token received from cloud wallet (if it passes the authentication and cloud wallet sent token back)
                        fetch("http://127.0.0.1:7777/eciespy/decrypt", {
                          method: "POST",
                          body: JSON.stringify({
                            sk_hex: this.state.sk_me_Alice,
                            data: r.token,
                          }),
                        })
                          .then((respon) => respon.json())
                          .then((r) => {
                            this.setState({ token: r.decrypted });
                            let header = new Headers();
                            // request access to cloud wallet with decrypted token
                            header.set(
                              "Authorization",
                              "Basic " +
                                btoa(this.state.token + ":" + "anything")
                            );
                            fetch("http://127.0.0.1:5000/api/connected", {
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
  // retrieve Alice's encrypted data from cloud wallet
  getResource = () => {
    let header2 = new Headers();
    // request Alice's resource with the token (get encrypted resource back if the token is authorized)
    header2.set(
      "Authorization",
      "Basic " + btoa(this.state.token + ":" + "anything")
    );
    fetch("http://127.0.0.1:5000/api/resource", {
      method: "GET",
      headers: header2,
    })
      .then((respon) => respon.json())
      .then((r) => {
        // decrypt the received encrypted data
        fetch("http://127.0.0.1:8000/umbral/decrypt", {
          method: "POST",
          body: JSON.stringify({
            sk_hex: this.state.sk_umbral_Alice,
            cipher_text: r.data,
            capsule_text: r.capsule,
          }),
        })
          .then((respon) => respon.json())
          .then((re) => this.setState({ value: re.decrypted }));
      });
  };

  // for sending the data and proxy re encryption key to Bob
  connectBob = () => {
    // create the re encryption key for Bob (using Alice's umbral secret key and Bob's umbral public key)
    fetch("http://127.0.0.1:8000/umbral/reencrypt", {
      method: "POST",
      body: JSON.stringify({
        sk_hex: this.state.sk_umbral_Alice,
        pk_reencrypt: this.state.pk_umbral_Bob,
      }),
    })
      .then((r) => r.json())
      .then((res) => {
        this.setState({ verifying_string_Alice: res.verifying_string });
        this.setState({ kfrag_string: res.kfrag_string });
        let header3 = new Headers();
        // control Alice's cloud wallet to send the data with corresponding necessary material for proxy re encryption
        // can only perform this step if Alice is authorized into her own cloud wallet (via authorized token)
        header3.set(
          "Authorization",
          "Basic " + btoa(this.state.token + ":" + "anything")
        );
        fetch("http://127.0.0.1:5000/api/sendToBob", {
          method: "POST",
          body: JSON.stringify({
            verifying_string: this.state.verifying_string_Alice,
            kfrag_string: this.state.kfrag_string,
          }),
          headers: header3,
        })
          .then((respon) => respon.json())
          .then((re) => this.setState({ bobstatus: re.name }));
      });
  };
  render() {
    return (
      <div>
        <h1 style={{ color: "orange" }}>Alice's Local wallet</h1>
        <button onClick={() => this.connectCloud()}>
          Connect Cloud Wallet
        </button>
        {/* show the status whether Alice is connected to her own cloud wallet or not */}
        <h1>{this.state.connect}</h1>
        <button onClick={() => this.getResource()}>Get data</button>
        {/* show the value of Alice's own resource (that is encrypted in her cloud wallet) */}
        <h1>{this.state.value}</h1>
        <button onClick={() => this.connectBob()}>Connect Bob</button>
        {/* show whether Alice sent the data to Bob yet or not */}
        <h1>{this.state.bobstatus}</h1>
      </div>
    );
  }
}
export default LocalAlice;
