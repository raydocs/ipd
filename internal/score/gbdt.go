package score

import (
	"encoding/json"
	"math"

	"ipd/models"
)

// Node is one GBDT split or leaf. The JSON is the published model.
type Node struct {
	Feature   string    `json:"feature,omitempty"`
	Threshold float64   `json:"threshold,omitempty"`
	Left      *Node     `json:"left,omitempty"`
	Right     *Node     `json:"right,omitempty"`
	Leaf      []float64 `json:"leaf,omitempty"`
}

// Forest is a sum of regression trees plus a softmax over classes.
type Forest struct {
	Version      string   `json:"version"`
	Classes      []string `json:"classes"`
	LearningRate float64  `json:"learning_rate"`
	Trees        []Node   `json:"trees"`
}

func loadForest() Forest {
	var f Forest
	if err := json.Unmarshal(models.ResidentialJSON, &f); err != nil {
		panic("residential.json: " + err.Error())
	}
	if f.LearningRate == 0 {
		f.LearningRate = 1
	}
	return f
}

func (n *Node) eval(features map[string]float64) []float64 {
	if n == nil {
		return nil
	}
	if len(n.Leaf) > 0 || (n.Left == nil && n.Right == nil) {
		return n.Leaf
	}
	if features[n.Feature] > n.Threshold {
		return n.Right.eval(features)
	}
	return n.Left.eval(features)
}

func (f Forest) predict(features map[string]float64) (class string, prob float64, probs []float64) {
	scores := make([]float64, len(f.Classes))
	for _, t := range f.Trees {
		leaf := t.eval(features)
		if leaf == nil {
			continue
		}
		for i := range scores {
			if i < len(leaf) {
				scores[i] += f.LearningRate * leaf[i]
			}
		}
	}
	probs = softmax(scores)
	best := 0
	for i := range probs {
		if probs[i] > probs[best] {
			best = i
		}
	}
	if len(f.Classes) == 0 {
		return "", 0, probs
	}
	return f.Classes[best], probs[best], probs
}

func softmax(xs []float64) []float64 {
	if len(xs) == 0 {
		return nil
	}
	max := xs[0]
	for _, v := range xs[1:] {
		if v > max {
			max = v
		}
	}
	out := make([]float64, len(xs))
	sum := 0.0
	for i, v := range xs {
		out[i] = math.Exp(v - max)
		sum += out[i]
	}
	for i := range out {
		out[i] /= sum
	}
	return out
}
