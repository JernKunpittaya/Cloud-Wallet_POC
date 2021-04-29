Finema’s POC: Secured Cloud Wallet 				by 	Teeramet (Jern) Kunpittaya


Summary:
	In this proof of concept, we simulate the main functions of cloud wallet and how it integrates with existing local wallet. Our main POC will address three issues.
1. Connect one’s local wallet with one’s own cloud wallet.
2. Securely store information on cloud wallet, and sync one’s information among multiple local devices of that person via cloud wallet.
3. Messaging interface among different people via cloud wallet.

For the sake of explaining, we have two users in our POC, Alice and Bob. We represent each of their local wallets with React.js while representing each of their cloud wallet as Flask Restful API on a python file. We will first explore what each of our code files does and then see how each of them interacts with one another to create the functional system that represents its real usage. Note that in this document, we will provide only a big picture. To see the code in detail, you can look at our comment in each code file.

Local Wallet
Since we simulate the behavior of both Alice’s and Bob’s local wallet via using React, we need another API to compute the necessary cryptography for it. We have two python files for these cryptography as follows.

1. crypto/crypto.py
This file contains two cryptography techniques:
	- eciespy is used for encrypting and decrypting with asymmetric keys (although inside mechanics still use symmetric keys, but from a high level we see it as using asymmetric keys). We use the default curve:secp256k1. We use this library for authentication when the local wallet is accessing its cloud wallet. 
	- Fastecdsa: for signing a digital signature, we set the curve to be secp256r1 to match with Finema’s. We use this library for authentication when the local wallet is trying to access its cloud wallet. 

We can build a docker by going into crypto folder and: docker build -t <username>/crypto .
Note that after building a docker, we need to run it with: docker run -p 7777:7777 <username>/crypto to make it run in localhost with port 7777

2.) umbral/UmbralEngine.py
	This is cryptography relating to using Umbral for proxy re encryption. Basically this library allows us to decrypt and encrypt the data by using its own asymmetric key with the curve that we set as secp256r1. We use this library to encrypt the data that we want to store on the cloud wallet. Once encrypted with umbral public key, we can perform the proxy re encryption by calling another method from this library so that we can send the encrypted data from our cloud wallet to the other cloud wallet without the need to pulling the data from our cloud wallet to our local wallet to decrypt and encrypt it again.
	
We can build a docker by going into umbral folder and run “docker build -t <username>/umbral”
Note that after building a docker, we need to run it with: “docker run -p 8000:8000 <username>/umbral” to make it run in localhost with port 8000

We need to run the above two cryptographic helper files (via port 7777 and 8000) for all the time during our demonstration of POC.

Now we investigate each of our main issues.

**1. Connect one’s local wallet with one’s own cloud wallet.**
We look at authentication between local and cloud wallets of the same person.
Note that we assume that we already did the registration on the cloud wallet, so the cloud wallet has information of the owner of the cloud wallet (which is Alice's did (which we represent with Alice's eciespy public key), public_sign1, public_sign2 for verifying the digital signature from Alice)

To see the demonstration, we have to run Alice’s local wallet and Alice’s cloud wallet.
- Alice’s local wallet: go into passwordless_pre_Alice folder and run “npm start” (This will run through port 3000)
- Alice’s cloud wallet: go into passwordless_pre_Alice/cloudAlice then run “docker build -t <username>/api .”
Note that after building a docker, we need to run it with “docker run -p 5000:5000 <username>/api” to make it run in localhost with port 5000

After running those, we can see the interface of Alice’s local wallet as follows.

![Alice01](https://user-images.githubusercontent.com/61564542/116531567-4f68aa00-a8ad-11eb-9fe9-59c52cfdf54d.png)



Once we click “Connect Cloud Wallet”, the following process happens.
- Alice’s local wallet will sign Alice’s DID by its private key for signing digital signature with ecdsa.
- Then the local wallet will encrypt (via eciespy) Alice’s DID with the public key of Alice’s cloud wallet.
- The local wallet also encrypts (via eciespy) the key pairs from signing Alice’s DID with ecdsa with the public key of Alice’s cloud wallet.
-Then, the local wallet sends the encrypted version of did and 2 key pairs to the cloud wallet to request the access token to the cloud wallet.
-Once the cloud wallet receives the information that are sent from the local wallet as we discussed above, it decrypts the encrypted did and 2 key pairs with its corresponding eciespy private key.
-Then, the cloud wallet looks up whether the decrypted DID is on its registered list of the owner of the cloud wallet or not. If not, it just aborts and rejects the request. 
-If the user exists, it now uses the decrypted value of two key pairs, together with already known public key of the user’s digital signature (the user that belongs to that DID), to check the digital signature. If it is tampered, it aborts and rejects the request.
-If the digital signature is valid, the cloud wallet generates authentication token based on the user’s did, secret text, and corresponding time. Then, the cloud wallet encrypts this token with the eciespy public key of the local wallet. (In our case, we use eciespy public key of the local wallet as the did of user’s local wallet.)
-Once the local wallet gets the encrypted token, it decrypts the token using its eciespy private key, and stores the decrypted token.
-Then, it makes another request to the cloud wallet again but this time with a token. Once the cloud wallet checks that the token is valid and not expired yet. It sends confirmation back to the local wallet. The local cloud will show “Connected to cloud agent successfully,” signaling that the local wallet successfully connects to the cloud wallet.

![Alice02](https://user-images.githubusercontent.com/61564542/116533713-b2f3d700-a8af-11eb-9c99-016c8f25e96e.png)

2. Securely store information on cloud wallet, and sync one’s information among multiple local devices of that person via cloud wallet.

To store information securely on the cloud wallet means that we need to encrypt information before storing on the cloud to not let anyone including the cloud provider able to see our data. As a result, we will encrypt our data which is a text “Secret of Alice encrypted with umbral!” via using our Umbral public key which will result in 2 components: secret text and capsule string. (In this context is Alice, we will discuss later why we use Umbral instead of eciespy for encrypting our data for storing on cloud agent)

Since now our cloud wallet has an encrypted version of “Secret of Alice encrypted with umbral!”, when we want to retrieve the data into our local wallet we can just click “Get data.” The following processes happen.
The local wallet makes the request to get the data from the cloud wallet with the token we have. 
The cloud wallet will check the token that we sent along with our request. If it is valid, the cloud wallet will return our data which was encrypted with Umbral and stay on the cloud. (Because of how Umbral works, we need to return both secret text and capsule string.) Note that we can see that in this process if we do not have the token or the token is not valid which can be seen if we do not have “Connected to cloud agent successfully” on our local wallet, our request to get the data from the cloud wallet will fail.
Once the local cloud wallet gets the secret text and capsule string, we can just decrypt it by using our private Umbral key and get the desired data “Secret of Alice encrypted with umbral!”


Crucial Point: Although this seems just like normal encrypting and decrypting stuff, it is not! What matters is how this structure interacts with our overall system as follows. First, we need to understand that one user can have multiple local devices but just one cloud wallet. Each of that device will have a different DID, public and private eciespy key, hence each device has to be registered separately with the cloud wallet to be able to get authenticated. However, all of these devices have the same public and private Umbral key, so each of them can retrieve and decrypted the data from the cloud wallet which is encrypted using the same public Umbral key. And most importantly, a cloud wallet does not have a private Umbral key , so it cannot see our encrypted data that is stored on the cloud wallet. So, this separation between umbral and eciespy allows us to syncing the same data across different local devices while also authenticating the local devices separately which makes it easy to revoke an access to cloud wallet for a specific device if that device is lost.



3. Messaging interface among different people via cloud wallet.


In this POC, we mock only the case when Alice sends the data to Bob. (Of course, in reality Bob also has to be able to send data to Alice, but it would be similar implementation anyway so in this POC our code supports only Alice sending data to Bob).
Now, we also need to run both Bob’s local wallet and cloud wallet.
-Bob’s local wallet: go into passwordless_pre_Bob folder and run “npm run” (This will run through port 3333)
-Bob’s cloud wallet: go into passwordless_pre_Bob/cloudBob then run “docker build -t <username>/apibob”
Note that after building a docker, we need to run it with “docker run -p 5555:5555 <username>/apibob” to make it run in localhost with port 5555.

Alice wants to send its encrypted data (2 components: ciphertext and capsule string) that is stored on its cloud wallet to Bob. 

Once we click “Connect Bob” on Alice’s local wallet, the following things happen.
1.Alice’s local wallet formulates a re-encryption key for Bob by using Alice’s Umbral private key and Bob’s Umbral public key. Alice’s re-encryption key is also signed with a digital signature by another generated Alice’s Umbral private key itself during the formulating the encryption key process. Hence, the local wallet generate kfrag_string (the re-encryption key) and verifying_string (for checking the signature of kfrags) 
	Note that in this POC, another private key that is generated for digital signature is randomly generated every time, and we can verify it by also sending verifying_string with it. Of course, we can do the other way, which is assigning a specific private key for Alice to sign the digital signature for re-encryption key and store its verifying_string on PKI.

2. Alice’s local wallet then sends the request along with kfrag_string and verifying_string to Alice’s cloud wallet (of course with the token, so if the token is not valid, Alice is not authorized to command the cloud wallet to send data to Bob).
3. Once Alice’s cloud wallet validates the token, it sends Alice’s encrypted data (ciphertext and capsule_string) along with kfrag_string and verifying_string to Bob’s cloud wallet. 
4. Once Bob’s cloud wallet receives the following information from Alice’s cloud wallet, it stores that information on its cloud wallet. Then, return the response to tell Alice’s cloud wallet that it already receives the message. Then Alice’s cloud wallet sent the message to Alice’s local wallet, confirming that “send to Bob successfully.”




Now we will look at the process of how Bob accesses the message sent from Alice. (He gets 4 chunks of information from Alice: ciphertext, capsule_string, kfrags, and verifying string.) 

We now switch to work on Bob’s local wallet, which shares the feature of “connect Cloud Wallet” to authenticate Bob’s local wallet to Bob’s cloud wallet, and the feature of “Get Bob’s own data” that simply retrieves or sync Bob’s data that is encrypted by his Umbral public key and is stored on Bob’s cloud wallet.



Now, when Bob wants to access Alice’s data from those unreadable chunks on his cloud wallet, he clicks “Get Alice’s data”, the process happens as follows.
1. Bob’s local wallet makes a request to Bob’s cloud wallet with the token.
2. Once Bob’s cloud wallet validates the token, it returns the four information about Alice’s data that we have described above back to Bob’s local wallet.
3. Once the local wallet gets those information, it simply performs decryption via using a re-encryption key to get clear text of Alice’s data that neither Alice’s nor Bob’s cloud wallets have seen. (Note that since Bob’s local wallet is implemented in React, to decrypt by using re-encryption of Umbral, we just need to make a request to RestFul API representing Umbral library.) We can see that in Bob’s local wallet now, we have Alice’s information (“Secret of Alice encrypted with umbral!”)




Now, since Bob already knows the clear text of what Alice has sent him, he no longer needs those four information of Alice’s data on his cloud wallet. Therefore, by clicking “Delete Alice’s data,” Bob can delete those 4 informations about Alice on his cloud wallet. (Of course, to be able to delete it, the local wallet needs to make a request with a valid token) Note that the Alice’s clear text in Bob’s local wallet is not deleted with this process.

Lastly, we have one more step left to do which is not implemented in the POC because it is very obvious and will have no problem to do. 

Now, if Bob wants to store Alice’s clear text data on his own cloud wallet, he just encrypts it with His own Umbral public key and just stores its component (capsule and ciphertext) on his cloud wallet). It is essential that Bob has to at least pull the 4 information about Alice’s data to decrypt in his local wallet first because we cannot re-encryption multiple times. Therefore, if Bob wants to send Alice’s data to Eve, he cannot just forward those 4 information to Eve because Eve cannot decrypt it since that pack of 4 information is re-encrypted only for Bob to decrypt. Therefore, Bob has to decrypt Alice’s data in his local wallet, then encrypt with his Umbral private key to store in his cloud. Then, once Bob wants to send his data to Eve, he just creates re-encryption key using his Umbral private key and Eve’s umbral public key. Then, send those components of re-encryption keys together with the components of encrypted data on cloud wallet to Eve’s cloud wallet, and Eve proceeds with the information the same way as Bob did with the data sent from Alice to him.

Optional: once Bob uploads his version of Alice’s data on cloud wallet (Alice’s clear text encrypted with Bob’s Umbral public key), he can delete Alice’s data stored in his local wallet.


During this Doc, you may encounter some variables that has the word “string” in it like capsule_string. That is just implementation details that do not matter much for the big picture in this document. However, to be able to understand the actual code, we describe what format of data we store as follows.
Hex string: most key like private eciespy key, or private Umbral key are stored as hex string.
String: since most of cryptographic algorithm returns the value as a byte, we format those bytes into string so that we can safely transport it over json. We format the byte to string via following steps.
-From byte, we encode with base64.
-Once we obtain that base 64 encode, we decode it with ‘ascii’ to get the string. (We need 2 steps because in Python base64 encoding outputs byte instead of string, so we need to decode them by ascii to obtain the string format) 
To get byte from our stored string, we just do it reversely. Note that this becomes clear as you look at our code and the comment around it. 

Another concept that is crucial to our implementation is to send the “raw content” of object instead of the actual object. For example, in Umbral, we cannot send Capsule object from one wallet to another wallet. So, we send the “raw content” of Capsule (In this case, just a byte of capsule that can be used to generate the capsule on the other end) Note that of course, in this POC, we format that byte to string via the way we described above before sending. 



The following is all related key information we used in this POC.
1=client=local wallet
2=server=cloud wallet
sk=secret key=private key
pk=public key

Alice
Alice:Proxy re encryption (Umbral)
skA: keys.UmbralPrivateKey(curvebn.CurveBN(backend._int_to_bn(0x000001F6F133A748),SECP256R1),config.default_params())

We can see that the raw content of Umbral private key of Alice is just 0x000001F6F133A748 and we just formulate the key as shown above.

pkA: keys.UmbralPublicKey(point.Point.from_bytes(b"\x033\x07x'l\xfc\xf1\xc9i~\x01;s\xea\x19\xaf\xaa\xcc\x98\xb5\xb5\x1d1\xd7\x90\x01/\x8b'Cs\x13"), params.UmbralParameters(SECP256R1))


Alice: Eciespy
sk1 0xa4207fcf1f7457b55a781873de7a2715a363bbea87f387b40b3c9dfaae63f7f9
pk1 0xc962736683a565d12dbc299b5a17d97fe53137af2a151766c741d5fbb1d1a873594c648f28702a01b7588d895c56763859e52d31c62abf9deb15659b497c9928
sk2 0xc60d216e58ca0eff4f2993195beb6f082c9fbe63ce89b93d368f7984e1eb84af
pk2 0x9d251415240aca8d926596bfe945fde874f4e4444709db76173d2a439cba30da0de1663c7709d8c399adb05a044eafc49aa1ab35f827fe32e7dd2d98a9d6cc34


Alice:ECDSA curve 256r1
private 55296113075965769983214099068001948551333506148419620277267301735931301306895
public X: 0x947599fe125266e93f2333cdc58ca61d4f6bcdcf12ee889632bac298a5d64c5
Y: 0x8dc63a6fd1ceef6cf3bbee9d0738762ce6e0af9bdd6c106abff5940a101cab30


Bob
Bob: Proxy re encryption (Umbral)
skB: keys.UmbralPrivateKey(curvebn.CurveBN(backend._int_to_bn(0x000002C84AE01688),SECP256R1),config.default_params())
pkB: keys.UmbralPublicKey(point.Point.from_bytes(b'\x03\xc7\xe5P\x1d\xd5\x84\x04\xb3\xbd6\xed\x84\x0b\x93\x8cO\xbe\xcd\xc9K\x91\x88\xe2\xe9xh\xfd\xa6\x87\x835\x9c'), params.UmbralParameters(SECP256R1))

Bob: Eciespy
sk1: 0xc1f3721a60df95b19f079a794eec9555f2afc2fe428df94fe5308bb4a5efad5a
pk1: 0x7fb36db75a49cc7b14011d1b88623749f33da2aa45b328aa4854337a0c0e7656241f14d56e2e91f8cbbc4d6fdc2cf3462bcfa1f14f79d537c3e58380f204c730
sk2: 0xc1538febd2c058fe9a4ad3525430e0b95776ee85f01bd163c1f4802df0725db8
pk2: 0xeb608b4d1002c74dd55636b70617bff5f13b4cf548c22fc224798a05cbb688036488a86d32118efd5f5cacc75996009b73f3fe214b15ada419da1c700e577f78

Bob: ECDSA curve 256r1
private 62542187512261159204913937044612363382356928282649244457036375298228417908947
public X: 0x7c9eef372063e609b9662b8ddb5d663c5a54ebd75c166ba8a811de9728615559
Y: 0x4fe08a04cb51549721b08f812d690149d554779dd232a16cf1ae60bb52a3c334






Further improvement
Although this POC validates the possibility of implementing a secure cloud wallet, there are lots of rooms for many more features to be implemented.
Ledger Communication. Currently in this POC, we assume that each wallet already has other person’s information like public key or verification key. However, in real life, we need to query that from ledger or blockchain, so this feature needs to be implemented once building a cloud wallet.
Separate EDV from identity hub. In this POC, we have one cloud wallet for one user, and we store every of that user’s information on this cloud wallet. In the future, we will represent that cloud wallet that is unique for each user as “identity hub”. However, we will not store all information on identity hub. Instead, we will store information on separate encrypted data vaults which one person can have many of those vaults. Identity hub will act as the means to access those encrypted data vault.
Communication protocol. We can see that in this POC, mostly we will secure the data by encrypting with the other’s public key before sending. (Note that in some processes in this POC, we do not encrypt before sending since it does not bring anything new to the POC, but in real life, encryption to secure data during transmitting is very crucial.) That being said, there are multiple ways to secure the transmission: DIDcomm, Https, etc.
 

