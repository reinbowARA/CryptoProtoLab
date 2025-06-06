package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"time"
)

// KC3RNG реализует генератор случайных чисел класса КС3
type KC3RNG struct {
	hmac    hash.Hash
	key     []byte
	value   []byte
	counter uint64
	entropy []byte
	reseed  uint64
}

// NewKC3RNG создает новый генератор с криптографически стойким заполнением
func NewKC3RNG() (*KC3RNG, error) {
	rng := &KC3RNG{
		key:     make([]byte, 64),
		value:   make([]byte, 64),
		entropy: make([]byte, 64),
	}

	if _, err := rand.Read(rng.entropy); err != nil {
		return nil, fmt.Errorf("ошибка получения энтропии: %v", err)
	}

	rng.hmac = hmac.New(sha512.New, rng.key)
	if err := rng.reseedNow(); err != nil {
		return nil, err
	}

	return rng, nil
}

func (r *KC3RNG) reseedNow() error {
	if _, err := rand.Read(r.entropy); err != nil {
		return fmt.Errorf("ошибка reseed: %v", err)
	}

	r.hmac.Reset()
	r.hmac.Write(r.value)
	r.hmac.Write(r.entropy)
	seed := r.hmac.Sum(nil)

	copy(r.key, seed[:64])
	copy(r.value, seed[64:])
	r.hmac.Reset()
	r.hmac.Write(r.key)

	r.counter = 0
	r.reseed += 64
	return nil
}

func (r *KC3RNG) Read(p []byte) (n int, err error) {
	if r.reseed > 1<<30 {
		if err := r.reseedNow(); err != nil {
			return 0, err
		}
	}

	for i := 0; i < len(p); {
		r.hmac.Reset()
		r.hmac.Write(r.value)

		if len(p)-i < 64 {
			var counterBytes [8]byte
			binary.BigEndian.PutUint64(counterBytes[:], r.counter)
			r.hmac.Write(counterBytes[:])
			r.counter++
		}

		r.value = r.hmac.Sum(nil)
		copyLen := min(64, len(p)-i)
		copy(p[i:i+copyLen], r.value[:copyLen])
		i += copyLen
		r.reseed += uint64(copyLen)
	}

	return len(p), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateRandomFile(filename string, size int) error {
	rng, err := NewKC3RNG()
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	buf := make([]byte, 1024*1024)
	for bytesWritten := 0; bytesWritten < size; {
		chunkSize := min(len(buf), size-bytesWritten)
		if _, err := rng.Read(buf[:chunkSize]); err != nil {
			return err
		}
		if _, err := file.Write(buf[:chunkSize]); err != nil {
			return err
		}
		bytesWritten += chunkSize
	}

	return nil
}

func generateRandomKeys(min, max int) ([][]byte, error) {
	rng, err := NewKC3RNG()
	if err != nil {
		return nil, err
	}

	countBuf := make([]byte, 8)
	if _, err := rng.Read(countBuf); err != nil {
		return nil, err
	}

	// Исправление: преобразование типов для операции modulo
	rangeSize := uint64(max - min + 1)
	count := min + int(binary.BigEndian.Uint64(countBuf)%rangeSize)

	keys := make([][]byte, count)
	for i := 0; i < count; i++ {
		key := make([]byte, 32)
		if _, err := rng.Read(key); err != nil {
			return nil, err
		}
		keys[i] = key
	}

	return keys, nil
}

func main() {
	fileSizes := []struct {
		size int
		name string
	}{
		{1 * 1024 * 1024, "random_1mb.bin"},
		{100 * 1024 * 1024, "random_100mb.bin"},
		{1000 * 1024 * 1024, "random_1000mb.bin"},
	}

	for _, fs := range fileSizes {
		start := time.Now()
		if err := generateRandomFile(fs.name, fs.size); err != nil {
			fmt.Printf("Ошибка генерации файла %s: %v\n", fs.name, err)
			continue
		}
		elapsed := time.Since(start)
		fmt.Printf("Сгенерирован файл %s (%d MB) за %v, скорость %.2f MB/s\n",
			fs.name, fs.size/(1024*1024), elapsed, float64(fs.size)/(1024*1024)/elapsed.Seconds())
	}

	start := time.Now()
	keys, err := generateRandomKeys(1000, 10000)
	if err != nil {
		fmt.Printf("Ошибка генерации ключей: %v\n", err)
		return
	}
	elapsed := time.Since(start)
	fmt.Printf("Сгенерировано %d ключей за %v, скорость %.2f ключей/сек\n",
		len(keys), elapsed, float64(len(keys))/elapsed.Seconds())

	if len(keys) > 0 {
		fmt.Printf("Первый ключ (hex): %x\n", keys[0])
	}
}