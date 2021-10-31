# Description

Ce répertoire est l'implémentation du projet "Pezos" réalisé par:

* Wenzhuo ZHAO
* Chengyu YANG
* Zhaojie LU
* Zhen HOU

# Diagramme de classes

![](https://dev.azure.com/zslyvain/9285f0e6-8055-4a5c-aec3-50d9555ac078/_apis/git/repositories/4eb461c6-bb1f-489f-978b-686e8c32decf/items?path=%2F1635685888102_6754.png&versionDescriptor%5BversionOptions%5D=0&versionDescriptor%5BversionType%5D=0&versionDescriptor%5Bversion%5D=master&resolveLfs=true&%24format=octetStream&api-version=5.0)



Les interactions sont composées par des échanges de messages applicatifs qui est typé par la classe `Message`. Les 9 types de message sont énumérés dans une `enum` classe `Application`.   

Un message applicatif peut apporter des informations supplémentaires, par exemple il faut donner le `level` pour un message `GET BLOCK <level>`. Ces informations supplémentaires, qui peuvent être 

* `Block`

* `SignedOperations`(séquences d'opérations signées)

*  `State` (Etat)

*  `Level`(niveau)

implémentent l'interface `Information` pour polymorphism.  Toutes ces classes filles réalisent la méthode `toBytesFromInformation` qui sert à convertir un objet vers un tableau de `byte`.

# Procédure

## Authentification

Une fois la connection TCP est établie, la communication commence par l'authentification. Pour assurer que l'authentification soit réussite, le client envoie un message `GET CURRENT HEAD` et attend la réponse du serveur. 

* Si la réponse est bien l'information du bloc courant(le plus récemment), nous utilisons cette information pour commencer à miner (trouver des erreurs)
* Si aucune réponse retournée dans un très délai maximum, nous pouvons constater que l'authentification est échouée.

## Miner

Il consisite à trouver des erreurs dans le bloc courant (renvoyé par la fonction `authentification` ci-dessus) pour gagner des `pez`.

Pour le bloc courant, des informations sont disponbiles pour la suite de vérifications:
* `level`
* `predecessor`
* `timestamp`
* `operations hash`
* `state hash`
* `siganture`

Aussi, une TCP connection (`TCPClient`) est disponbile pour envoyer et recevoir des messages pour des informations éventuellement nécessaires.

### Vérification du prédecesseur
Dans cette partie, nous demandons le contenu du bloc précédent au serveur par envoyer un message `GET BLOCK<level - 1>`. Puis nous hachons sa représentation encodée et le comparer avec `predecessor` du `GET BLOCK<level>`.
Si la comparaison renvoie `True`, nous savons que `predecessor` de ce blc est correct. Sinon, nous ajoutons ce message d'error et la correction pour `INJECT`.

### Vérification du timestamp
Pour vérifier le timestamp, nous prenons aussi les contenus du bloc et de bloc précédent et decoder `timestamp` en type `long`. En comparant les deux `timestamp`, nous avons la différence. Si la différence est moins de 10 minutes, nous pouvons dire qu'il est erronné et ajouter ce message d'error et la correction pour `INJECT`.Sinon, nous savons que `timestamp` de ce bloc est correct.


### Vérification des hash opérations
En envoyant un message `GET BLOCK OPERATIONS <level>`, le client peut obtenir une liste de toutes opérations. Avec une function récursive `opsHash`, nous pouvons donner une correcte valeur hash de liste des opérations. En comparant cette valeur avec celle donnée dans le bloc, nous pouvons dire la valeur Operations Hash donnée dans bloc est correcte ou erronée et donner la correction pour `INJECT`.


### Vérification de hash state
Le bloc obtenu contient une valeur du hash de l’état `hashstate`, cette valeur peut être erroné.  Par conséquence, nous devons vérifier cette valeur en comparant avec la  valeur correcte. 

Pour obtenir sa valeur correcte, nous avons envoyé au serveur un message `GET_STATE <level>` en initial, puis nous pouvons stocker la réponse en `Information State`, enfin "ré-hash" ces bytes qui donner une correcte valeur hash de l'état. 

Selon la comparaison entre cette valeur avec celle donnée dans le bloc, nous allons donner la correction à l'aider de l'opération`INJECT`.


### Vérification de signature
Le bloc contient la signature produite par le dictateur. Pour vérifier le signature, d'abord nous prenons la clé
publique du dictateur dans l’état de la chaîne et les contenus du bloc sans le champ signature. En utilisant la fonction de hachage Blake2b et l’algorithme de signature Ed25519, nous faisons le hachage du sous-ensemble du bloc et procédons à notre vérification de signature.

## Inject des opérations de dénonciation
Après avoir fait les vérifications ci-dessus, nous récupérons les corrections puis les envoyons au serveur. En attendant 10 minutes pour le bloc suivant, nous pouvons savoir le montant de `pez` que nous obtenons pour la dénonciation.

## Logs
Voici des logs (journal) que nous imprimons pour l'interaction entre le client et serveur.

```
15:24:54.360 [main] INFO TCPClient - Receive Seed: 
FE8DDC0247317A00EF8632A76FCBBF2747FAAA75FF82D294
15:24:54.373 [main] INFO TCPClient - Send Public Key: 
BFB86CA90EB0D4B6818AFF69C60261C87F67406FF90505BD7B8BE60D4194C11C
15:24:54.380 [main] INFO TCPClient - Send Signature: 
E7BB2AB39C0564A670C537464706EA8392DDA461617CF70E1D4F70259F048D145F2C381A669E3E6D5D0C181F7EE814DC0EB5F47DDD411323304AC65C3D601100
15:24:54.380 [main] INFO TCPClient - Send Message: 
1 - GET CURRENT HEAD
15:24:54.727 [main] INFO TCPClient - Receive Block information: 
2 - CURRENT HEAD: 
level: 2881
hashPredecessor: B8592B1816805B111DBC71E01B2D0FC94D2317CCD7FA5500BF2E4B24020C5F1C
timestamp: 2021-10-31 15:20:00.0
hashOperations: CABD6D10C9E47382277D57C1760FBBCE682260D5DACF5F591FCFAD93A3723771
hashState: 8A7B5A94DDFCC92B93EECBF3B122E2479C78AFDB28BC9D6D16DEA68C3F103709
signature: 802F0BDEC3DACC752BE85E5F16E5184CDB70780ED1C7EE71C81AE1BCC0009D0ED1D248E31AF9BE236D6331DCC6B08BB2D0B7C4B643AF8798DE8FF2A4D4A88C09
15:24:54.728 [main] INFO TCPClient - 
----------Authentication success----------
15:24:54.728 [main] INFO TCPClient - Send Message: 
3 - GET BLOCK 2880
15:24:54.896 [main] INFO Block - Receive Block information: 
4 - BLOCK: 
level: 2880
hashPredecessor: 50DE184593B9D1E3043EA0FACFB78D81EDA844E5788B953C664A02BDFA4487BE
timestamp: 1987-10-07 01:52:47.0
hashOperations: CDB22CD843D2A1E818C164605638807B9275267174AC1E31E8E4845DD20CEA42
hashState: 97CBBB254AACE97C8D3004D9B5F734DCF58F8FBE5824399ABEF3576B2C12FFDB
signature: 6D5A140FE683CBBD4D03F2AE96A5B266AB618C9F869EC554EAC0211BC1C1844ACE7B50381016B4E1008628BAB58494745E8D4A289B8D421309654CA27BD46E0F
15:24:54.896 [main] INFO TCPClient - Send Message: 
7 - GET STATE 2881
15:24:55.082 [main] INFO Block - Receive Block 2881's state: 
8 - BLOCK STATE: 
dictator_public_key: 2DFD3FB419C78E23806D6BE7C2BCC1DEF9DFCD2D6EFCC86260A86E4BD9F0ACE6
timestamp: 2021-10-31 15:10:00.0
byte size of accounts: 884
accounts:
user_public_key: 013375B4CE8AB350CFE690E73F17B791010FD709822F841B3DA43D604DEEE6AE
predecessor_pez: 584
timestamp_pez: 586
operations_hash_pez: 557
context_hash_pez: 585
signature_pez: 566
----------------------------
user_public_key: 17DAB198DF998BD72A3AF9C3799354ADE0E294CE76360C465240BF273B4A8282
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 2B49C18F70AFB1067E7928F3D0A550530397A2A5F707072D17227B10C2A2FD90
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 37B9AD00A0292ABCFDB4C6BCAF55736968F857136EFAA45732AF1F64FDD250EF
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 37E5712E91E47B4CF757A6DF1551E3A16CE129AA12972F8243557E9799F7BD79
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 4CE8BF7261570FF5A1B30B2426DE5F0B7A4659C880E3AFAFF16C01C6CF74CCEC
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 5BC085C535C4F8404D5E8364FFF6AB40B44A249015CD7F26B12343517665BC8F
predecessor_pez: 274
timestamp_pez: 301
operations_hash_pez: 252
context_hash_pez: 288
signature_pez: 305
----------------------------
user_public_key: 7677D5A38F085BEFB69508671478AF9D01B8D9684463CA66584CBC90CA9D8D8F
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 7C4331D10BFFAB2E5FD79D3C678367672293EA93372782EE08813CBB163119EC
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: 97572375D32CAEDF7B12832B7BF78346F8733576A20DCB7C21EE613CFE38BFE2
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: AB4843CA25D80D51E1D077102FC8335937DDCAE8365084B51A85454BDF936011
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: ACA76354DE343EF09385E263FB59561855D3CBF167961C6955624D91AA7EECF5
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: B8B606DBA2410E1F3C3486E0D548A3053BA3F907860FADA6FAB2835FB27B3F21
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: BFB86CA90EB0D4B6818AFF69C60261C87F67406FF90505BD7B8BE60D4194C11C
predecessor_pez: 405
timestamp_pez: 333
operations_hash_pez: 374
context_hash_pez: 401
signature_pez: 409
----------------------------
user_public_key: C46DF4074F404A10E0A8F7F96D29B375B3CDB2AE871AB47BC8BA29A417F0225C
predecessor_pez: 0
timestamp_pez: 0
operations_hash_pez: 0
context_hash_pez: 0
signature_pez: 0
----------------------------
user_public_key: E522991D21D463BAD9B74498A22172AE22B133E486ADCEDBB3A56D982E6A31FD
predecessor_pez: 39
timestamp_pez: 37
operations_hash_pez: 45
context_hash_pez: 45
signature_pez: 58
----------------------------
user_public_key: FE2DFFFA926409103BBE584149846C69041EEA30E987E079633877F9BA4DC6C5
predecessor_pez: 10
timestamp_pez: 21
operations_hash_pez: 21
context_hash_pez: 10
signature_pez: 21
----------------------------

15:24:55.096 [main] INFO TCPClient - Send Message: 
5 - GET BLOCK OPERATIONS 2881
15:24:55.258 [main] INFO Block - Receive Block 2881's operations: 
6 - BLOCK OPERATIONS: 
2 - BAD TIMESTAMP: 
2021-10-31 15:10:00.0
2 - BAD TIMESTAMP: 
2021-10-31 15:10:00.0

15:24:55.267 [main] INFO TCPClient - Send Message: 
9 - INJECT OPERATION: 
4 - BAD CONTEXT HASH: 
EC2830CE5DCA293150A496681CC46B45BDB26B1B0FADF4DF11994E34C3A3EF9B
15:24:55.267 [main] INFO TCPClient - 
----------Your Account Information----------
user_public_key: BFB86CA90EB0D4B6818AFF69C60261C87F67406FF90505BD7B8BE60D4194C11C
predecessor_pez: 405
timestamp_pez: 333
operations_hash_pez: 374
context_hash_pez: 401
signature_pez: 409
--------------------------------------------
15:24:55.268 [main] INFO TCPClient - 
Waiting for next block...
```