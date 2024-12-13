package main

import (
	"bufio"
	util "chess"
	"chess/game"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/notnil/chess"
	"net"
	"strings"
	"sync"
)

type HelloRequest struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	FirstName string `json:"first_name"`
	Status    bool   `json:"status"`
	Level     int    `json:"level"`
	Signature string `json:"signature"`
}

type HelloResponse struct {
	Type            string `json:"type"`
	ServerSignature string `json:"server_signature"`
}

type GameRequest struct {
	Type       string `json:"type"`
	TargetSign string `json:"target_sign"`
}

type GameChallenge struct {
	Type     string `json:"type"`
	FromName string `json:"from_name"`
	FromSign string `json:"from_sign"`
}

type GameChallengeResponse struct {
	Type     string `json:"type"`
	Accepted bool   `json:"accepted"`
}

type GameResponse struct {
	Type     string `json:"type"`
	Accepted bool   `json:"accepted"`
	Key      string `json:"key,omitempty"`
}

type PlayerConnection struct {
	Conn          net.Conn
	Role          chess.Color
	Signature     string
	Name          string
	EncryptionKey []byte
	InGame        bool
	Opponent      *PlayerConnection
	Partie        *game.Partie
	NullRequested bool
	ClientUUID    string
	GameUUID      string
}

var (
	waitingPlayers     []*PlayerConnection
	playersLock        sync.Mutex
	pendingChallenges  = make(map[string]chan bool)
	pendingChallengesM sync.Mutex
)

func main() {
	tcpListener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("[SERVER] Erreur lors de l'écoute TCP :", err)
		return
	}
	defer tcpListener.Close()
	fmt.Println("[SERVER] Serveur en écoute TCP sur le port 8080...")

	udpAddr, err := net.ResolveUDPAddr("udp", ":8081")
	if err != nil {
		fmt.Println("[SERVER] Erreur lors de la résolution de l'adresse UDP :", err)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("[SERVER] Erreur lors de l'écoute UDP :", err)
		return
	}
	defer udpConn.Close()
	fmt.Println("[SERVER] Serveur en écoute UDP sur le port 8081...")

	go func() {
		handleUDPConnection(udpConn)
	}()

	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			fmt.Println("[SERVER] Erreur lors de l'acceptation TCP :", err)
			continue
		}
		fmt.Println("[SERVER] Nouvelle connexion acceptée :", conn.RemoteAddr())
		go handleNewConnection(conn)
	}
}

func handleNewConnection(conn net.Conn) {
	defer conn.Close()
	message, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Println("[SERVER] Erreur de lecture du HelloRequest :", err)
		return
	}

	var helloReq HelloRequest
	err = json.Unmarshal([]byte(strings.TrimSpace(message)), &helloReq)
	if err != nil || helloReq.Type != "hello_request" {
		fmt.Println("[SERVER] Requête initiale invalide ou mal formée")
		return
	}

	serverSignature := util.GenerateRandomSHA256()
	hRes := HelloResponse{
		Type:            "hello_response",
		ServerSignature: serverSignature,
	}
	hBytes, _ := json.Marshal(hRes)
	_, err = conn.Write(append(hBytes, '\n'))
	if err != nil {
		fmt.Println("[SERVER] Erreur lors de l'envoi de HelloResponse :", err)
		return
	}
	fmt.Println("[SERVER] HelloResponse envoyé à", helloReq.Name, helloReq.FirstName)

	player := &PlayerConnection{
		Conn:       conn,
		Signature:  helloReq.Signature,
		Name:       fmt.Sprintf("%s %s", helloReq.FirstName, helloReq.Name),
		ClientUUID: util.GenerateUUID(),
	}

	playersLock.Lock()
	waitingPlayers = append(waitingPlayers, player)
	playersLock.Unlock()

	fmt.Printf("[SERVER] Joueur ajouté : %s (%s)\n", player.Name, player.Signature)

	sendAvailablePlayersUnlocked(conn)

	uuidTLV := util.EncodeTLV(1, player.ClientUUID, nil)
	b64 := base64.StdEncoding.EncodeToString(uuidTLV)
	player.Conn.Write([]byte(b64 + "\n"))
	fmt.Println("[SERVER] ClientUUID envoyé (Base64+TLV):", player.ClientUUID)

	handlePlayerConnection(player)
}

func sendAvailablePlayersUnlocked(conn net.Conn) {
	playersLock.Lock()
	defer playersLock.Unlock()

	availablePlayers := []string{}
	for _, p := range waitingPlayers {
		availablePlayers = append(availablePlayers, fmt.Sprintf("%s (%s)", p.Name, p.Signature))
	}

	response := map[string]interface{}{
		"type":    "available_players",
		"players": availablePlayers,
	}
	resBytes, _ := json.Marshal(response)
	_, err := conn.Write(append(resBytes, '\n'))
	if err != nil {
		fmt.Println("[SERVER] Erreur lors de l'envoi de available_players :", err)
		return
	}
	fmt.Println("[SERVER] Liste des joueurs disponibles envoyée")
}

func handlePlayerConnection(player *PlayerConnection) {
	reader := bufio.NewReader(player.Conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("[SERVER] Déconnexion de %s : %v\n", player.Name, err)
			removePlayer(player.Signature)
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if !player.InGame {
			var baseMsg map[string]interface{}
			if err := json.Unmarshal([]byte(line), &baseMsg); err != nil {
				fmt.Println("[SERVER] Message mal formé avant la partie :", line)
				continue
			}

			msgType, ok := baseMsg["type"].(string)
			if !ok {
				fmt.Println("[SERVER] Type de message inconnu avant la partie :", line)
				continue
			}

			switch msgType {
			case "game_request":
				var gameReq GameRequest
				if err := json.Unmarshal([]byte(line), &gameReq); err != nil {
					fmt.Println("[SERVER] Erreur parsing GameRequest :", err)
					continue
				}
				startGameWithRequest(player, gameReq)

			case "solo_game_request":
				fmt.Println("[SERVER] Reçu solo_game_request")
				startSoloGame(player)

			case "game_challenge_response":
				var chResp GameChallengeResponse
				if err := json.Unmarshal([]byte(line), &chResp); err != nil {
					fmt.Println("[SERVER] Erreur parsing GameChallengeResponse :", err)
					continue
				}

				pendingChallengesM.Lock()
				respChan, ok := pendingChallenges[player.Signature]
				if ok {
					respChan <- chResp.Accepted
					delete(pendingChallenges, player.Signature)
				} else {
					fmt.Printf("[SERVER] Aucun challenge en attente pour %s\n", player.Signature)
				}
				pendingChallengesM.Unlock()

			case "save_game":
				filename, _ := baseMsg["filename"].(string)
				if !player.InGame || player.Partie == nil {
					errMsg := "Aucune partie en cours à sauvegarder."
					sendJSONResponse(player, "save_response", false, errMsg)
					continue
				}
				err := player.Partie.SauvegarderPartie(filename)
				if err != nil {
					sendJSONResponse(player, "save_response", false, err.Error())
				} else {
					sendJSONResponse(player, "save_response", true, "")
				}
			case "load_game":
				filename, _ := baseMsg["filename"].(string)
				loadedPartie, err := game.ChargerPartie(filename)
				if err != nil {
					sendJSONResponse(player, "load_response", false, err.Error())
					continue
				}
				player.Partie = loadedPartie
				sendJSONResponse(player, "load_response", true, "Partie chargée avec succès.")
				sendJSONResponse(player, "choose_mode", true, "Voulez-vous jouer en solo ou défier un autre joueur ?")
			default:
				fmt.Println("[SERVER] Message inconnu avant la partie :", msgType)
			}
		} else {
			var baseMsg map[string]interface{}
			err := json.Unmarshal([]byte(line), &baseMsg)
			if err == nil {
				msgType, _ := baseMsg["type"].(string)
				switch msgType {
				case "save_game":
					filename, _ := baseMsg["filename"].(string)
					if player.Partie == nil {
						sendJSONResponse(player, "save_response", false, "Aucune partie en cours à sauvegarder.")
						continue
					}
					err := player.Partie.SauvegarderPartie(filename)
					if err != nil {
						sendJSONResponse(player, "save_response", false, err.Error())
					} else {
						sendJSONResponse(player, "save_response", true, "")
					}
					continue

				default:
					fmt.Printf("[SERVER] Type de message inconnu reçu de %s : %s\n", player.Name, msgType)
				}
			}

			moveBytes, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				fmt.Println("[SERVER] Erreur Base64 en jeu :", err)
				sendEncryptedMessage(player, "Erreur de décodage du message.\n")
				continue
			}

			decrypted, err := util.DecryptMessage(player.EncryptionKey, moveBytes)
			if err != nil {
				fmt.Println("[SERVER] Erreur de décryptage en jeu :", err)
				sendEncryptedMessage(player, "Erreur de décryptage du message.\n")
				continue
			}

			tag, uuid, value, err := util.DecodeTLV(decrypted)
			if err != nil {
				fmt.Println("[SERVER] Erreur de décodage TLV en jeu :", err)
				sendEncryptedMessage(player, "Erreur de décodage TLV.\n")
				continue
			}

			if uuid != player.GameUUID {
				fmt.Printf("[SERVER] UUID partie inattendu en jeu : %s (attendu : %s)\n", uuid, player.GameUUID)
				sendEncryptedMessage(player, "UUID de partie invalide.\n")
				continue
			}

			if tag != 40 {
				fmt.Printf("[SERVER] Tag TLV inattendu en jeu : %d\n", tag)
				sendEncryptedMessage(player, "Tag TLV inconnu en jeu.\n")
				continue
			}

			move := string(value)
			handleEncryptedMove(player, move)
		}
	}
}

func startGameWithRequest(p1 *PlayerConnection, gameReq GameRequest) {
	playersLock.Lock()
	var p2 *PlayerConnection
	for _, p := range waitingPlayers {
		if p.Signature == gameReq.TargetSign && p.Signature != p1.Signature {
			p2 = p
			break
		}
	}
	playersLock.Unlock()

	if p2 == nil {
		fmt.Printf("[SERVER] Joueur cible %s introuvable pour %s\n", gameReq.TargetSign, p1.Name)
		p1.Conn.Write([]byte("Joueur cible introuvable.\n"))
		return
	}

	challenge := GameChallenge{
		Type:     "game_challenge",
		FromName: p1.Name,
		FromSign: p1.Signature,
	}
	chBytes, _ := json.Marshal(challenge)
	p2.Conn.Write(append(chBytes, '\n'))
	fmt.Printf("[SERVER] Challenge envoyé de %s à %s\n", p1.Name, p2.Name)

	respChan := make(chan bool, 1)
	pendingChallengesM.Lock()
	pendingChallenges[p2.Signature] = respChan
	pendingChallengesM.Unlock()

	accepted := <-respChan
	if !accepted {
		gr := GameResponse{Type: "game_response", Accepted: false}
		grBytes, _ := json.Marshal(gr)
		p1.Conn.Write(append(grBytes, '\n'))
		return
	}

	encryptionKey := util.GenerateEncryptionKey()
	p1.EncryptionKey = encryptionKey
	p2.EncryptionKey = encryptionKey
	p1.InGame = true
	p2.InGame = true
	p1.Opponent = p2
	p2.Opponent = p1

	if p1.Partie == nil {
		p1.Partie = game.NewPartie()
	}
	partie := p1.Partie
	p2.Partie = partie

	p1.Role = chess.White
	p2.Role = chess.Black
	p1.GameUUID = util.GenerateUUID()
	p2.GameUUID = p1.GameUUID

	gameTLV := util.EncodeTLV(2, p1.GameUUID, nil)
	b64 := base64.StdEncoding.EncodeToString(gameTLV)
	p1.Conn.Write([]byte(b64 + "\n"))
	p2.Conn.Write([]byte(b64 + "\n"))

	gr := GameResponse{Type: "game_response", Accepted: true, Key: hex.EncodeToString(encryptionKey)}
	grBytes, _ := json.Marshal(gr)
	p1.Conn.Write(append(grBytes, '\n'))
	p2.Conn.Write(append(grBytes, '\n'))

	sendActionResponse(p1, 140, p1.GameUUID, "Vous êtes les Blancs.\n")
	sendActionResponse(p2, 140, p2.GameUUID, "Vous êtes les Noirs.\n")

	boardState := partie.AfficherÉchiquier()
	moves := strings.Join(partie.CoupsPossibles(), " ")
	msg := fmt.Sprintf("%s\nCoups possibles: %s\n", boardState, moves)
	sendActionResponse(p1, 140, p1.GameUUID, msg)
	sendActionResponse(p2, 140, p2.GameUUID, msg)
}

func handleEncryptedMove(player *PlayerConnection, move string) {
	partie := player.Partie

	switch move {
	case "suggérer":
		suggestion, err := partie.MeilleurCoup()
		if err != nil {
			sendActionResponse(player, 140, player.GameUUID, "Impossible de suggérer un coup.\n")
		} else {
			sendActionResponse(player, 140, player.GameUUID, "Suggestion: "+suggestion+"\n")
		}
		return

	case "nulle":
		if player.Opponent == nil {
			sendActionResponse(player, 140, player.GameUUID, "Aucun adversaire.\n")
			return
		}

		if player.Opponent.NullRequested {
			sendActionResponse(player, 140, player.GameUUID, "Votre adversaire a proposé une nulle. Partie terminée.\n")
			sendActionResponse(player.Opponent, 140, player.GameUUID, "Votre proposition de nulle a été acceptée.\n")
			player.InGame = false
			player.Opponent.InGame = false
		} else {
			player.NullRequested = true
			sendActionResponse(player.Opponent, 140, player.GameUUID, fmt.Sprintf("%s propose une nulle. Acceptez-vous ? (o/n)\n", player.Name))
		}
		return
	}

	if (partie.CouleurCourante() == chess.White && player.Role != chess.White) ||
		(partie.CouleurCourante() == chess.Black && player.Role != chess.Black) {
		sendActionResponse(player, 140, player.GameUUID, "Ce n'est pas votre tour.\n")
		return
	}

	err := partie.JouerCoup(move)
	if err != nil {
		fmt.Printf("[SERVER] Coup invalide de %s : %s\n", player.Name, move)
		sendActionResponse(player, 140, player.GameUUID, "Coup invalide.\n")
		return
	}

	boardState := partie.AfficherÉchiquier()
	moves := strings.Join(partie.CoupsPossibles(), " ")
	msg := fmt.Sprintf("%s\nCoups possibles: %s\n", boardState, moves)

	sendActionResponse(player, 140, player.GameUUID, msg)
	if player.Opponent != nil {
		sendActionResponse(player.Opponent, 140, player.GameUUID, msg)
	}

	if partie.État() != chess.NoOutcome {
		resultMessage := fmt.Sprintf("Partie terminée : %s", partie.État())
		sendActionResponse(player, 140, player.GameUUID, resultMessage)
		if player.Opponent != nil {
			sendActionResponse(player.Opponent, 140, player.GameUUID, resultMessage)
		}
		player.InGame = false
		if player.Opponent != nil {
			player.Opponent.InGame = false
		}
		return
	}

	if player.Opponent == nil {
		fmt.Println("[SERVER] Partie solo : le serveur joue un coup.")
		jouerCoupServeur(player)
	}
}

func removePlayer(signature string) {
	playersLock.Lock()
	defer playersLock.Unlock()

	for i, p := range waitingPlayers {
		if p.Signature == signature {
			fmt.Printf("[SERVER] Suppression du joueur : %s (%s)\n", p.Name, p.Signature)
			if p.InGame && p.Opponent != nil {
				sendActionResponse(p.Opponent, 140, p.GameUUID, "Votre adversaire s'est déconnecté. Partie terminée.")
				p.Opponent.InGame = false
			}
			waitingPlayers = append(waitingPlayers[:i], waitingPlayers[i+1:]...)
			break
		}
	}
}

func sendActionResponse(player *PlayerConnection, tag int, uuid, message string) {
	tlv := util.EncodeTLV(tag, uuid, []byte(message))
	enc, err := util.EncryptMessage(player.EncryptionKey, tlv)
	if err != nil {
		fmt.Println("[SERVER] Erreur chiffrement sendActionResponse pour", player.Name, ":", err)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(enc)
	player.Conn.Write([]byte(b64 + "\n"))
}

func sendEncryptedMessage(player *PlayerConnection, message string) {
	enc, err := util.EncryptMessage(player.EncryptionKey, []byte(message))
	if err != nil {
		fmt.Printf("[SERVER] Erreur de chiffrement pour %s : %v\n", player.Name, err)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(enc)
	_, err = player.Conn.Write(append([]byte(b64), '\n'))
	if err != nil {
		fmt.Printf("[SERVER] Erreur lors de l'envoi du message chiffré à %s : %v\n", player.Name, err)
	}
}

func startSoloGame(p1 *PlayerConnection) {
	if p1.Partie == nil {
		p1.Partie = game.NewPartie()
	}

	encryptionKey := util.GenerateEncryptionKey()
	p1.EncryptionKey = encryptionKey
	p1.InGame = true
	p1.Opponent = nil
	p1.Role = chess.White
	p1.GameUUID = util.GenerateUUID()

	gameTLV := util.EncodeTLV(2, p1.GameUUID, nil)
	b64 := base64.StdEncoding.EncodeToString(gameTLV)
	p1.Conn.Write([]byte(b64 + "\n"))

	gr := GameResponse{
		Type:     "game_response",
		Accepted: true,
		Key:      hex.EncodeToString(encryptionKey),
	}
	grBytes, _ := json.Marshal(gr)
	p1.Conn.Write(append(grBytes, '\n'))

	sendActionResponse(p1, 140, p1.GameUUID, "Vous êtes les Blancs.\n")
	boardState := p1.Partie.AfficherÉchiquier()
	moves := strings.Join(p1.Partie.CoupsPossibles(), " ")
	msg := fmt.Sprintf("%s\nCoups possibles: %s\n", boardState, moves)
	sendActionResponse(p1, 140, p1.GameUUID, msg)
}

func jouerCoupServeur(player *PlayerConnection) {
	partie := player.Partie
	if partie.État() != chess.NoOutcome {
		return
	}

	suggestion, err := partie.MeilleurCoupAvecStockfish()
	if err != nil || suggestion == "" {
		resultMessage := fmt.Sprintf("Partie terminée : %s", partie.État())
		sendActionResponse(player, 140, player.GameUUID, resultMessage)
		player.InGame = false
		return
	}

	err = partie.JouerCoup(suggestion)
	if err != nil {
		sendActionResponse(player, 140, player.GameUUID, "Le serveur ne peut pas jouer de coup.\n")
		player.InGame = false
		return
	}

	sendActionResponse(player, 140, player.GameUUID, fmt.Sprintf("Le serveur a joué : %s\n", suggestion))

	boardState := partie.AfficherÉchiquier()
	moves := strings.Join(partie.CoupsPossibles(), " ")
	msg := fmt.Sprintf("%s\nCoups possibles: %s\n", boardState, moves)
	sendActionResponse(player, 140, player.GameUUID, msg)

	if partie.État() != chess.NoOutcome {
		resultMessage := fmt.Sprintf("Partie terminée : %s", partie.État())
		sendActionResponse(player, 140, player.GameUUID, resultMessage)
		player.InGame = false
	}
}

func handleUDPConnection(conn *net.UDPConn) {
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("[SERVER] Erreur lors de la lecture UDP :", err)
			continue
		}

		fmt.Printf("[SERVER] Message reçu via UDP de %s : %s\n", addr, string(buffer[:n]))

		_, err = conn.WriteToUDP([]byte("Message reçu via UDP"), addr)
		if err != nil {
			fmt.Println("[SERVER] Erreur lors de l'envoi UDP :", err)
		}
	}
}

func sendJSONResponse(player *PlayerConnection, msgType string, success bool, errMsg string) {
	resp := map[string]interface{}{
		"type":    msgType,
		"success": success,
	}
	if errMsg != "" {
		resp["error"] = errMsg
	}
	data, _ := json.Marshal(resp)
	player.Conn.Write(append(data, '\n'))
}
