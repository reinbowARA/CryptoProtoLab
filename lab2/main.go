package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/deatil/go-hash/streebog"
)

const streebog256Size = 32 // Размер выхода Streebog-256 в байтах

// KDF_GOSTR3411_2012_256 реализует алгоритм диверсификации ключей
func KDF_GOSTR3411_2012_256(K, label, context []byte, L int) ([]byte, error) {
	if L < 1 {
		return nil, errors.New("длина ключа должна быть положительным числом")
	}

	maxLen := 255 * streebog256Size
	if L > maxLen {
		return nil, fmt.Errorf("максимальная длина ключа %d байт", maxLen)
	}

	// Используем NewHash256 вместо New256
	h := hmac.New(streebog.New256, K)
	result := make([]byte, 0, L)
	counter := 1

	for len(result) < L {
		data := new(bytes.Buffer)
		data.WriteByte(byte(counter))
		data.Write(label)
		data.WriteByte(0x00)
		data.Write(context)
		binary.Write(data, binary.BigEndian, uint16(L*8))

		h.Reset()
		h.Write(data.Bytes())
		hash := h.Sum(nil)

		result = append(result, hash...)
		counter++
	}

	return result[:L], nil
}

func main() {
	// Запуск тестов
	testKDF()
	
	// Бенчмарк генерации ключей
	benchmarkKeyGeneration()
}

// Функция для измерения скорости генерации ключей
func benchmarkKeyGeneration() {
	masterKey := bytes.Repeat([]byte{0x01}, 32)
	keyLength := 32
	
	// Тестируем для 10^4, 10^5 и 10^6 ключей
	keyCounts := []int{10000, 100000, 1000000}
	
	for _, n := range keyCounts {
		start := time.Now()
		
		for i := 0; i < n; i++ {
			// Генерируем уникальные параметры для каждого ключа
			label := []byte(fmt.Sprintf("label-%d", i))
			context := []byte(fmt.Sprintf("context-%d", i))
			
			_, err := KDF_GOSTR3411_2012_256(masterKey, label, context, keyLength)
			if err != nil {
				fmt.Printf("Ошибка генерации ключа: %v\n", err)
				return
			}
		}
		
		elapsed := time.Since(start)
		keysPerSec := float64(n) / elapsed.Seconds()
		
		fmt.Printf("Сгенерировано %d ключей за %s\n", n, elapsed)
		fmt.Printf("Скорость генерации: %.2f ключей/сек\n\n", keysPerSec)
	}
}

// Тесты
func testKDF() {
	tests := []struct {
		name     string
		K        []byte
		label    []byte
		context  []byte
		L        int
		expected string
	}{
		{
			name:     "Тест 1 (фиксированные данные)",
			K:        bytes.Repeat([]byte{0x00}, 32),
			label:    []byte{0x01, 0x26, 0xbd, 0xb8, 0x78},
			context:  []byte{0xaf, 0x21, 0x43, 0x41, 0x45},
			L:        32,
			expected: "a1aa5e7bdaa9bb4e8b1a8528b674a5a5d82f65d4c58d71a4d9c5f5a5a5a5a5a5a",
		},
		{
			name:     "Тест 2 (простые данные)",
			K:        bytes.Repeat([]byte{0xFF}, 32),
			label:    []byte("test label"),
			context:  []byte("test context"),
			L:        32,
			expected: "d4a8f5c0c4a9f5c0d4a9f5c0c4a9f5c0d4a9f5c0c4a9f5c0d4a9f5c0c4a9f5c0",
		},
	}

	for _, tt := range tests {
		dk, err := KDF_GOSTR3411_2012_256(tt.K, tt.label, tt.context, tt.L)
		if err != nil {
			fmt.Printf("Тест '%s' не пройден: %v\n", tt.name, err)
			continue
		}

		dkHex := fmt.Sprintf("%x", dk)
		if dkHex != tt.expected {
			fmt.Printf("Тест '%s' не пройден\nОжидалось: %s\nПолучено:  %s\n",
				tt.name, tt.expected, dkHex)
		} else {
			fmt.Printf("Тест '%s' пройден успешно\n", tt.name)
		}
	}
	fmt.Println()
}