package main

import (
	"bufio"
	util "chess"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

type Challenge struct {
	FromName string
	FromSign string
}

type Config struct {
	ServerAddress string `json:"server_address"`
	Protocol      string `json:"protocol"`
	Port          int    `json:"port"`
}

var (
	encryptionKey []byte
	clientUUID    string
	gameUUID      string
	inGame        bool
)

func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		fmt.Println("[CLIENT] Erreur de lecture de la configuration :", err)
		return
	}

	address := fmt.Sprintf("%s:%d", config.ServerAddress, config.Port)
	fmt.Printf("[CLIENT] Connexion au serveur %s via %s...\n", address, config.Protocol)

	var conn net.Conn
	if config.Protocol == "tcp" {
		conn, err = net.Dial("tcp", address)
	} else if config.Protocol == "udp" {
		conn, err = net.Dial("udp", address)
	} else {
		fmt.Println("[CLIENT] Protocole inconnu :", config.Protocol)
		return
	}

	if err != nil {
		fmt.Println("[CLIENT] Erreur de connexion :", err)
		return
	}
	defer conn.Close()
	fmt.Println("[CLIENT] Connecté au serveur.")

	fmt.Println("Entrez votre nom :")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	clientName := scanner.Text()

	clientSignature := util.GenerateClientSignature()
	fmt.Println("[CLIENT] Signature générée :", clientSignature)

	helloReq := map[string]interface{}{
		"type":       "hello_request",
		"name":       clientName,
		"first_name": "John",
		"status":     true,
		"level":      100,
		"signature":  clientSignature,
	}
	hBytes, _ := json.Marshal(helloReq)
	conn.Write(append(hBytes, '\n'))
	fmt.Println("[CLIENT] HelloRequest envoyé.")

	reader := bufio.NewReader(conn)
	serverMsg, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("[CLIENT] Erreur de lecture de HelloResponse :", err)
		return
	}
	var hRes map[string]interface{}
	json.Unmarshal([]byte(strings.TrimSpace(serverMsg)), &hRes)
	fmt.Println("[CLIENT] HelloResponse reçu (signature serveur):", hRes["server_signature"])

	serverMsg, err = reader.ReadString('\n')
	if err != nil {
		fmt.Println("[CLIENT] Erreur de lecture de la liste des joueurs :", err)
		return
	}
	var playerList map[string]interface{}
	json.Unmarshal([]byte(strings.TrimSpace(serverMsg)), &playerList)
	fmt.Println("[CLIENT] Joueurs disponibles :", playerList["players"])

	serverMsg, err = reader.ReadString('\n')
	if err != nil {
		fmt.Println("[CLIENT] Erreur de lecture du clientUUID :", err)
		return
	}
	tlvBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(serverMsg))
	if err != nil {
		fmt.Println("[CLIENT] Erreur Base64 clientUUID :", err)
		return
	}
	tag, uuidStr, _, err := util.DecodeTLV(tlvBytes)
	if err != nil || tag != 1 {
		fmt.Println("[CLIENT] Erreur de décodage TLV de l'UUID client :", err)
		return
	}
	clientUUID = uuidStr
	fmt.Println("[CLIENT] UUID du client reçu :", clientUUID)

	challengesChan := make(chan Challenge)
	inputChan := make(chan string)

	go listenFromServer(conn, challengesChan)
	go readUserInput(inputChan)

	fmt.Println("[CLIENT] Tapez 'defier', 'attendre', 'suggérer', 'nulle', 'charger' ou 'solo' pour interagir.")

	for {
		select {
		case challenge := <-challengesChan:
			fmt.Printf("Vous avez une demande de partie de %s (%s). Accepter ? (o/n):\n", challenge.FromName, challenge.FromSign)
			rep := <-inputChan
			accepted := strings.ToLower(strings.TrimSpace(rep)) == "o"

			chResp := map[string]interface{}{
				"type":     "game_challenge_response",
				"accepted": accepted,
			}
			chBytes, _ := json.Marshal(chResp)
			conn.Write(append(chBytes, '\n'))
			fmt.Println("[CLIENT] GameChallengeResponse envoyé :", chResp)

		case input := <-inputChan:
			action := strings.ToLower(strings.TrimSpace(input))
			if inGame {
				if action == "sauver" {
					fmt.Println("[CLIENT] Entrez le nom du fichier pour sauvegarder la partie :")
					targetFile := <-inputChan
					targetFile = strings.TrimSpace(targetFile)
					if targetFile == "" {
						fmt.Println("[CLIENT] Nom de fichier vide. Annulation.")
						continue
					}
					saveReq := map[string]interface{}{
						"type":     "save_game",
						"filename": targetFile,
					}
					sBytes, _ := json.Marshal(saveReq)
					conn.Write(append(sBytes, '\n'))
					fmt.Println("[CLIENT] Demande de sauvegarde envoyée.")
					continue
				}
				if action == "" {
					fmt.Println("[CLIENT] Mouvement vide. Réessayer.")
					continue
				}
				fmt.Println("[CLIENT] Mouvement saisi :", action)
				plaintextTLV := util.EncodeTLV(40, gameUUID, []byte(action))
				encryptedTLV, err := util.EncryptMessage(encryptionKey, plaintextTLV)
				if err != nil {
					fmt.Println("[CLIENT] Erreur de chiffrement du TLV :", err)
					continue
				}
				b64 := base64.StdEncoding.EncodeToString(encryptedTLV)
				conn.Write([]byte(b64 + "\n"))
				fmt.Println("[CLIENT] Mouvement envoyé.")

			} else {
				switch action {
				case "defier":
					fmt.Println("[CLIENT] Entrez la signature du joueur cible :")
					targetSign := <-inputChan
					targetSign = strings.TrimSpace(targetSign)
					if targetSign == "" {
						fmt.Println("[CLIENT] Signature vide. Abandon du défi.")
						continue
					}
					gReq := map[string]interface{}{
						"type":        "game_request",
						"target_sign": targetSign,
					}
					gBytes, _ := json.Marshal(gReq)
					conn.Write(append(gBytes, '\n'))
					fmt.Println("[CLIENT] GameRequest envoyé.")
				case "suggérer":
					suggestionRequest := util.EncodeTLV(40, clientUUID, []byte("suggestion"))
					conn.Write(append(suggestionRequest, '\n'))
					fmt.Println("[CLIENT] Demande de suggestion envoyée.")
				case "nulle":
					nullRequest := util.EncodeTLV(40, clientUUID, []byte("null"))
					conn.Write(append(nullRequest, '\n'))
					fmt.Println("[CLIENT] Proposition de nulle envoyée.")
				case "attendre":
					fmt.Println("[CLIENT] Vous attendez un défi...")
				case "solo":
					soloReq := map[string]interface{}{
						"type": "solo_game_request",
					}
					sBytes, _ := json.Marshal(soloReq)
					conn.Write(append(sBytes, '\n'))
					fmt.Println("[CLIENT] Demande de partie solitaire envoyée.")
				case "charger":
					fmt.Println("[CLIENT] Entrez le nom du fichier de sauvegarde à charger :")
					targetFile := <-inputChan
					targetFile = strings.TrimSpace(targetFile)
					if targetFile == "" {
						fmt.Println("[CLIENT] Nom de fichier vide. Annulation.")
						continue
					}

					loadReq := map[string]interface{}{
						"type":     "load_game",
						"filename": targetFile,
					}
					lBytes, _ := json.Marshal(loadReq)
					conn.Write(append(lBytes, '\n'))
					fmt.Println("[CLIENT] Demande de chargement envoyée.")
				default:
					fmt.Println("[CLIENT] Action inconnue hors-jeu :", action)
				}
			}
		}
	}
}

func listenFromServer(conn net.Conn, challengesChan chan<- Challenge) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("[CLIENT] Déconnecté du serveur.")
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var baseMsg map[string]interface{}
		jsonErr := json.Unmarshal([]byte(line), &baseMsg)
		if jsonErr == nil {
			msgType, _ := baseMsg["type"].(string)
			switch msgType {
			case "game_response":
				accepted, _ := baseMsg["accepted"].(bool)
				if accepted {
					keyStr, _ := baseMsg["key"].(string)
					key, err := hex.DecodeString(keyStr)
					if err == nil {
						encryptionKey = key
						inGame = true
						fmt.Println("[CLIENT] Partie acceptée. Clé définie, inGame = true.")
					} else {
						fmt.Println("[CLIENT] Erreur décodage clé de chiffrement.")
					}
				} else {
					fmt.Println("[CLIENT] Partie refusée.")
				}
				continue

			case "game_challenge":
				fromName, _ := baseMsg["from_name"].(string)
				fromSign, _ := baseMsg["from_sign"].(string)
				challengesChan <- Challenge{
					FromName: fromName,
					FromSign: fromSign,
				}
				fmt.Println("[CLIENT] Défi reçu de :", fromName)
				continue

			case "suggestion_response":
				fmt.Println("[CLIENT] Suggestion reçue :", baseMsg["move"])
				continue

			case "null_response":
				accepted, _ := baseMsg["accepted"].(bool)
				if accepted {
					fmt.Println("[CLIENT] L'adversaire a accepté la nulle. La partie est terminée.")
					inGame = false
				} else {
					fmt.Println("[CLIENT] L'adversaire a refusé la nulle.")
				}
				continue

			case "available_players":
				fmt.Println("[CLIENT] Joueurs disponibles :", baseMsg["players"])
				continue

			case "save_response":
				success, _ := baseMsg["success"].(bool)
				if success {
					fmt.Println("[CLIENT] Sauvegarde réussie.")
				} else {
					fmt.Println("[CLIENT] Échec de la sauvegarde :", baseMsg["error"])
				}
				continue

			case "load_response":
				success, _ := baseMsg["success"].(bool)
				if success {
					fmt.Println("[CLIENT] Partie chargée avec succès.")
					fmt.Println("[CLIENT] Voulez-vous jouer en solo ou défier un autre joueur ? (tapez 'solo' ou 'defier')")
				} else {
					fmt.Println("[CLIENT] Échec du chargement :", baseMsg["error"])
				}
				continue

			case "choose_mode":
				fmt.Println("[CLIENT]", baseMsg["error"])
				fmt.Println("[CLIENT] Tapez 'solo' ou 'defier'.")
				continue

			default:
				fmt.Println("[CLIENT] Message JSON inconnu :", msgType)
				continue
			}
		}

		if inGame {
			encBytes, err := base64.StdEncoding.DecodeString(line)
			if err == nil {
				decrypted, err := util.DecryptMessage(encryptionKey, encBytes)
				if err == nil {
					tag, uuid, value, err := util.DecodeTLV(decrypted)
					if err == nil && tag == 140 {
						if uuid == gameUUID {
							fmt.Println(string(value))
							continue
						} else {
							fmt.Println("[CLIENT] UUID partie inattendu :", uuid)
							continue
						}
					}
				}
			}
			fmt.Println("[CLIENT] Message inconnu inGame :", line)
			continue
		} else {
			tlvData, err := base64.StdEncoding.DecodeString(line)
			if err == nil {
				tag, uuid, _, err := util.DecodeTLV(tlvData)
				if err == nil {
					switch tag {
					case 2:
						gameUUID = uuid
						fmt.Println("[CLIENT] GameUUID reçu :", gameUUID)
						continue
					default:
						fmt.Println("[CLIENT] Tag TLV inconnu hors-jeu :", tag)
						continue
					}
				}
			}
			fmt.Println("[CLIENT]", line)
		}
	}
}

func readUserInput(inputChan chan<- string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := scanner.Text()
		inputChan <- input
	}
	close(inputChan)
}

func loadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
