package game

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/notnil/chess"
	"github.com/notnil/chess/uci"
	"os"
	"time"
)

type Partie struct {
	Game *chess.Game
}

type PartieSnapshot struct {
	FEN  string `json:"fen"`
	Tour string `json:"tour"`
}

func NewPartie() *Partie {
	fmt.Println("[GAME] Nouvelle partie créée.")
	return &Partie{Game: chess.NewGame()}
}

func (p *Partie) JouerCoup(input string) error {
	legalMoves := p.Game.ValidMoves()
	fmt.Printf("[GAME] Coups légaux pour %s : ", p.Game.Position().Turn())
	for _, move := range legalMoves {
		fmt.Printf("%s ", move.String())
	}
	fmt.Println()

	for _, move := range legalMoves {
		if move.String() == input {
			fmt.Printf("[GAME] Application du coup : %s\n", move.String())
			return p.Game.Move(move)
		}
	}
	fmt.Printf("[GAME] Coup invalide : %s\n", input)
	return errors.New("coup invalide")
}

func (p *Partie) CoupsPossibles() []string {
	legalMoves := p.Game.ValidMoves()
	moves := []string{}
	for _, move := range legalMoves {
		moves = append(moves, move.String())
	}
	return moves
}

func (p *Partie) AfficherÉchiquier() string {
	boardStr := p.Game.Position().Board().Draw()
	fmt.Println("[GAME] Échiquier actuel :")
	fmt.Println(boardStr)
	return boardStr
}

func (p *Partie) État() chess.Outcome {
	return p.Game.Outcome()
}

func (p *Partie) CouleurCourante() chess.Color {
	return p.Game.Position().Turn()
}

func (p *Partie) MeilleurCoup() (string, error) {
	legalMoves := p.Game.ValidMoves()
	if len(legalMoves) > 0 {
		return legalMoves[0].String(), nil
	}
	return "", errors.New("aucun coup possible")
}

func (p *Partie) MeilleurCoupAvecStockfish() (string, error) {
	stockfishPath := "./stockfish/stockfish"
	eng, err := uci.New(stockfishPath)
	if err != nil {
		return "", fmt.Errorf("erreur lors de la configuration de Stockfish : %v", err)
	}
	defer eng.Close()

	if err := eng.Run(uci.CmdUCI, uci.CmdIsReady, uci.CmdUCINewGame); err != nil {
		return "", fmt.Errorf("erreur lors de l'initialisation de Stockfish : %v", err)
	}

	cmdPos := uci.CmdPosition{
		Position: p.Game.Position(),
	}
	if err := eng.Run(cmdPos); err != nil {
		return "", fmt.Errorf("erreur lors de la configuration de la position : %v", err)
	}

	cmdGo := uci.CmdGo{MoveTime: time.Second / 2}
	if err := eng.Run(cmdGo); err != nil {
		return "", fmt.Errorf("erreur lors de la recherche du meilleur coup : %v", err)
	}

	bestMove := eng.SearchResults().BestMove
	return bestMove.String(), nil
}

func (p *Partie) SauvegarderPartie(fichier string) error {
	snapshot := PartieSnapshot{
		FEN:  p.Game.FEN(),
		Tour: p.CouleurCourante().String(),
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("erreur lors de la sérialisation JSON : %v", err)
	}

	err = os.WriteFile(fichier, data, 0644)
	if err != nil {
		return fmt.Errorf("erreur lors de la sauvegarde dans le fichier : %v", err)
	}

	return nil
}

func ChargerPartie(fichier string) (*Partie, error) {
	data, err := os.ReadFile(fichier)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la lecture du fichier : %v", err)
	}

	var snapshot PartieSnapshot
	err = json.Unmarshal(data, &snapshot)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de la désérialisation JSON : %v", err)
	}

	option, err := chess.FEN(snapshot.FEN)
	if err != nil {
		return nil, fmt.Errorf("erreur lors de l'application de la position FEN : %v", err)
	}

	jeu := chess.NewGame(option)

	partie := &Partie{
		Game: jeu,
	}

	return partie, nil
}
