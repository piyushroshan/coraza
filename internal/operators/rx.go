// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.rx

package operators

import (
	"fmt"
	stdregexp "regexp"
	"strconv"
	"sync"
	"unicode/utf8"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/memoize"
	re2 "github.com/wasilibs/go-re2"
	"rsc.io/binaryregexp"
)

type reType int

const (
	reTypeUnknown reType = iota
	reTypeRE2
	reTypeStd
)

type regexEngine interface {
	MatchString(s string) bool
	FindStringSubmatch(s string) []string
}

type rx struct {
	engine regexEngine
}

var _ plugintypes.Operator = (*rx)(nil)

func newRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	var data string
	if shouldNotUseMultilineRegexesOperatorByDefault {
		data = fmt.Sprintf("(?s)%s", options.Arguments)
	} else {
		data = fmt.Sprintf("(?sm)%s", options.Arguments)
	}

	if matchesArbitraryBytes(data) {
		return newBinaryRX(options)
	}

	reType := detectRegexEngine()

	switch reType {
	case reTypeRE2:
		re, err := re2.Compile(data)
		if err != nil {
			return nil, err
		}
		return &rx{engine: re}, nil

	default: // fallback to std + memoize
		re, err := memoize.Do(data, func() (interface{}, error) { return stdregexp.Compile(data) })
		if err != nil {
			return nil, err
		}
		return &rx{engine: re.(*stdregexp.Regexp)}, nil
	}
}

func (o *rx) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if tx.Capturing() {
		match := o.engine.FindStringSubmatch(value)
		if len(match) == 0 {
			return false
		}
		for i, c := range match {
			tx.CaptureField(i, c)
		}
		return true
	} else {
		return o.engine.MatchString(value)
	}
}

// binaryRx is exactly the same as rx, but using the binaryregexp package for matching
// arbitrary bytes.
type binaryRX struct {
	re *binaryregexp.Regexp
}

var _ plugintypes.Operator = (*binaryRX)(nil)

func newBinaryRX(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	re, err := memoize.Do(data, func() (interface{}, error) { return binaryregexp.Compile(data) })
	if err != nil {
		return nil, err
	}
	return &binaryRX{re: re.(*binaryregexp.Regexp)}, nil
}

func (o *binaryRX) Evaluate(tx plugintypes.TransactionState, value string) bool {
	if tx.Capturing() {
		match := o.re.FindStringSubmatch(value)
		if len(match) == 0 {
			return false
		}
		for i, c := range match {
			if i == 9 {
				return true
			}
			tx.CaptureField(i, c)
		}
		return true
	} else {
		return o.re.MatchString(value)
	}
}

func init() {
	Register("rx", newRX)
}

// matchesArbitraryBytes checks for control sequences for byte matches in the expression.
// If the sequences are not valid utf8, it returns true.
func matchesArbitraryBytes(expr string) bool {
	decoded := make([]byte, 0, len(expr))
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if c != '\\' {
			decoded = append(decoded, c)
			continue
		}
		if i+3 >= len(expr) {
			decoded = append(decoded, expr[i:]...)
			break
		}
		if expr[i+1] != 'x' {
			decoded = append(decoded, expr[i])
			continue
		}

		v, mb, _, err := strconv.UnquoteChar(expr[i:], 0)
		if err != nil || mb {
			decoded = append(decoded, expr[i])
			continue
		}
		decoded = append(decoded, byte(v))
		i += 3
	}
	return !utf8.Valid(decoded)
}

var (
	cachedRegexEngine reType
	detectOnce        sync.Once
)

func detectRegexEngine() reType {
	detectOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				cachedRegexEngine = reTypeStd
			}
		}()

		re, err := re2.Compile("test")
		if err != nil {
			cachedRegexEngine = reTypeStd
			return
		}

		_ = re.MatchString("")
		cachedRegexEngine = reTypeRE2
	})
	return cachedRegexEngine
}
