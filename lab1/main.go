package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

)

// --------------------------------------------
// Реализация алгоритма "Кузнечик" (GOST R 34.12-2015)
// --------------------------------------------

var (
	sBox = [256]byte{
		0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
		0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
		0xF9, 0x18, 0x65, 0x5A, 0xE8, 0x03, 0x95, 0x5F, 0x2E, 0xD3, 0x8D, 0xC2, 0x2A, 0xAF, 0x72, 0x47,
		0x13, 0x13, 0x3A, 0xCA, 0x5B, 0x05, 0x6C, 0x52, 0x2F, 0x50, 0xBE, 0x7E, 0x2A, 0xD4, 0xE7, 0x9F,
		0x24, 0xA3, 0x85, 0x26, 0x6B, 0xBA, 0x32, 0xE6, 0x2C, 0xE2, 0xE3, 0x60, 0x3B, 0xE3, 0x9E, 0x77,
		0x9C, 0x8A, 0x24, 0x1E, 0xD6, 0x83, 0x0A, 0x9D, 0xAA, 0xE0, 0x50, 0x7E, 0x75, 0x87, 0xB3, 0x0F,
		0xBD, 0x63, 0x25, 0x6A, 0x52, 0xD5, 0x41, 0xA3, 0x8A, 0x0C, 0x2C, 0xD5, 0x14, 0xFD, 0x65, 0x52,
		0x03, 0xE3, 0x3D, 0x5C, 0x60, 0x67, 0x17, 0x0A, 0x2D, 0xCC, 0x03, 0x8F, 0x3A, 0xE9, 0x22, 0xDF,
		0x3B, 0x68, 0xC4, 0x0F, 0x64, 0x72, 0x2A, 0xE1, 0xBA, 0xEA, 0xDD, 0xFB, 0x62, 0x15, 0x85, 0x9A,
		0x33, 0x66, 0x62, 0x0E, 0xD2, 0x6F, 0x98, 0x2B, 0x31, 0xBD, 0x98, 0xE4, 0xDB, 0x80, 0x20, 0x36,
		0xE5, 0x57, 0x05, 0x2E, 0x30, 0x99, 0xA5, 0x42, 0x25, 0x08, 0x1E, 0x4A, 0xAB, 0x0B, 0xA9, 0x7F,
		0x62, 0x1C, 0x2D, 0x26, 0x28, 0x65, 0x92, 0x95, 0x93, 0x88, 0x41, 0xFE, 0x54, 0xC1, 0x2D, 0x4B,
		0x1E, 0x4F, 0xC2, 0x68, 0x2E, 0xFD, 0x84, 0x2B, 0x59, 0x46, 0xBB, 0x7D, 0x8D, 0x7A, 0x27, 0xEB,
		0x49, 0x5C, 0xC3, 0x9B, 0xA1, 0x1A, 0xCB, 0x56, 0x8F, 0x19, 0xAF, 0x5D, 0x0A, 0x71, 0x7C, 0x45,
		0x22, 0xD3, 0x9A, 0xEE, 0x96, 0x46, 0x6D, 0x84, 0x50, 0xEF, 0xA1, 0x73, 0x16, 0x5A, 0x4C, 0x2C,
		0x14, 0xAE, 0xF4, 0x6C, 0xB9, 0x6F, 0xDB, 0xD7, 0x24, 0x6A, 0x37, 0x15, 0xE0, 0x55, 0x38, 0x7C,
	}

	c = [32]byte{
		0x6e, 0xa2, 0x70, 0x9f, 0x7d, 0x30, 0xc8, 0x5f, 0xeb, 0xcd, 0x5f, 0x30, 0x89, 0xfe, 0x95, 0x62,
		0xf7, 0x0b, 0x60, 0x81, 0x91, 0x44, 0x66, 0x50, 0x52, 0x13, 0x42, 0xec, 0x3f, 0xcd, 0xbe, 0xae,
	}
)

type Kuznechik struct {
	roundKeys [10][16]byte
}

func NewKuznechik(key []byte) (*Kuznechik, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key size (must be 32 bytes)")
	}

	k := &Kuznechik{}
	k.expandKey(key)
	return k, nil
}

func (k *Kuznechik) BlockSize() int { return 16 }

func (k *Kuznechik) Encrypt(dst, src []byte) {
	var state [16]byte
	copy(state[:], src)

	for i := 0; i < 9; i++ {
		xorBlock(state[:], k.roundKeys[i][:])
		sTransform(state[:])
		state = lTransform(state)
	}
	xorBlock(state[:], k.roundKeys[9][:])
	copy(dst, state[:])
}

func (k *Kuznechik) Clear() {
	for i := range k.roundKeys {
		for j := range k.roundKeys[i] {
			k.roundKeys[i][j] = 0
		}
	}

	mem := unsafe.Slice((*byte)(unsafe.Pointer(&k.roundKeys)), unsafe.Sizeof(k.roundKeys))
	for i := range mem {
		mem[i] = 0
	}
}

func xorBlock(dst, src []byte) {
	for i := 0; i < 16; i++ {
		dst[i] ^= src[i]
	}
}

func sTransform(state []byte) {
	for i := 0; i < 16; i++ {
		state[i] = sBox[state[i]]
	}
}

func lTransform(input [16]byte) [16]byte {
	var output [16]byte
	for i := 0; i < 16; i++ {
		var v byte
		for j := 0; j < 16; j++ {
			v ^= gfMul(input[j], lMatrix[i][j])
		}
		output[i] = v
	}
	return output
}

func gfMul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0xC3
		}
		b >>= 1
	}
	return p
}

var lMatrix = [16][16]byte{
	{0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01},
	{0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94},
	{0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20},
	{0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85},
	{0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10},
	{0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2},
	{0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0},
	{0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01},
	{0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB},
	{0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01},
	{0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0},
	{0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10, 0xC2},
	{0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85, 0x10},
	{0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20, 0x85},
	{0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94, 0x20},
	{0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01, 0x94},
}

func (k *Kuznechik) expandKey(key []byte) {
	var k1, k2 [16]byte
	copy(k1[:], key[:16])
	copy(k2[:], key[16:])

	k.roundKeys[0] = k1
	k.roundKeys[1] = k2

	keyIndex := 0
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			var cVec [16]byte
			cVec[15] = c[keyIndex]
			keyIndex = (keyIndex + 1) % len(c)

			xorBlock(k1[:], cVec[:])
			sTransform(k1[:])
			k1 = lTransform(k1)

			if j == 7 {
				k.roundKeys[2*(i+1)] = k1
				k.roundKeys[2*(i+1)+1] = k2
			}

			tmp := k2
			xorBlock(tmp[:], k1[:])
			k1, k2 = k2, tmp
		}
	}
}

// --------------------------------------------
// Режим OFB
// --------------------------------------------
func NewOFB(block cipher.Block, iv []byte) cipher.Stream {
	if len(iv) != block.BlockSize() {
		panic("IV length must equal block size")
	}
	return &ofbStream{block: block, iv: iv}
}

type ofbStream struct {
	block cipher.Block
	iv    []byte
	out   []byte
	used  int
}

func (s *ofbStream) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if s.used == 0 {
			s.out = make([]byte, s.block.BlockSize())
			s.block.Encrypt(s.out, s.iv)
			s.iv = s.out
		}
		dst[i] = src[i] ^ s.out[s.used]
		s.used = (s.used + 1) % s.block.BlockSize()
	}
}

// --------------------------------------------
// Безопасные буферы
// --------------------------------------------
type SecureBuffer struct {
	data []byte
}

func NewSecureBuffer(size int) *SecureBuffer {
	data := make([]byte, size)
	return &SecureBuffer{data: data}
}

func (b *SecureBuffer) Bytes() []byte {
	return b.data
}

func (b *SecureBuffer) Clear() {
	if b.data == nil {
		return
	}
	for i := range b.data {
		b.data[i] = 0
	}
	b.data = nil
}

var SecurePool = sync.Pool{
	New: func() interface{} {
		return NewSecureBuffer(32)
	},
}

// --------------------------------------------
// Система авторизации и ролевого доступа
// --------------------------------------------
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
)

type User struct {
	Username string
	Password string
	Role     string
	IsActive bool
}

type Session struct {
	Token    string
	Username string
	Expiry   time.Time
}

type EncryptionKey struct {
	key       *SecureBuffer
	CreatedAt time.Time
	Expiry    time.Time
	CreatedBy string
	IsActive  bool
}

func (k *EncryptionKey) Key() []byte {
	if k.key == nil {
		return nil
	}
	return k.key.Bytes()
}

func (k *EncryptionKey) Clear() {
	if k.key != nil {
		k.key.Clear()
		k.key = nil
	}
	k.IsActive = false
}

type AuthSystem struct {
	users      map[string]*User
	sessions   map[string]*Session
	keys       map[string]*EncryptionKey
	currentKey string
	auditLog   []string
	mu         sync.Mutex
}

func NewAuthSystem() *AuthSystem {
	auth := &AuthSystem{
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
		keys:     make(map[string]*EncryptionKey),
		auditLog: make([]string, 0),
	}
	auth.CreateUser("system", "admin", "securepassword", RoleAdmin)
	return auth
}

func (a *AuthSystem) CreateUser(actor, username, password, role string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if actor != "system" {
		user, exists := a.users[actor]
		if !exists || user.Role != RoleAdmin || !user.IsActive {
			return errors.New("access denied")
		}
	}

	if role != RoleAdmin && role != RoleOperator && role != RoleAuditor {
		return errors.New("invalid role")
	}

	a.users[username] = &User{
		Username: username,
		Password: password,
		Role:     role,
		IsActive: true,
	}

	a.audit("USER_CREATE", actor, fmt.Sprintf("Created user: %s (%s)", username, role))
	return nil
}

func (a *AuthSystem) Login(username, password string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[username]
	if !exists || user.Password != password || !user.IsActive {
		return "", errors.New("authentication failed")
	}

	token := generateToken()
	expiry := time.Now().Add(24 * time.Hour)

	a.sessions[token] = &Session{
		Token:    token,
		Username: username,
		Expiry:   expiry,
	}

	a.audit("LOGIN", username, "User logged in")
	return token, nil
}

func (a *AuthSystem) CheckSession(token string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	session, exists := a.sessions[token]
	if !exists {
		return "", errors.New("session not found")
	}

	if time.Now().After(session.Expiry) {
		delete(a.sessions, token)
		return "", errors.New("session expired")
	}

	return session.Username, nil
}

func (a *AuthSystem) CreateKey(actor string, validity time.Duration) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[actor]
	if !exists || (user.Role != RoleAdmin && user.Role != RoleOperator) || !user.IsActive {
		return "", errors.New("access denied")
	}

	keyBuf := SecurePool.Get().(*SecureBuffer)
	keyData := keyBuf.Bytes()

	if _, err := rand.Read(keyData); err != nil {
		keyBuf.Clear()
		SecurePool.Put(keyBuf)
		return "", err
	}

	keyID := generateKeyID()
	created := time.Now()
	expiry := created.Add(validity)

	a.keys[keyID] = &EncryptionKey{
		key:       keyBuf,
		CreatedAt: created,
		Expiry:    expiry,
		CreatedBy: actor,
		IsActive:  true,
	}

	a.currentKey = keyID

	a.audit("KEY_CREATE", actor, fmt.Sprintf("Created key: %s (expiry: %s)", keyID, expiry.Format(time.RFC3339)))
	return keyID, nil
}

func (a *AuthSystem) GetActiveKey(actor string) (*SecureBuffer, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[actor]
	if !exists || !user.IsActive {
		return nil, "", errors.New("access denied")
	}

	if a.currentKey == "" {
		return nil, "", errors.New("no active key")
	}

	key, exists := a.keys[a.currentKey]
	if !exists || !key.IsActive {
		return nil, "", errors.New("active key not found")
	}

	if time.Now().After(key.Expiry) {
		key.IsActive = false
		return nil, "", errors.New("key expired")
	}

	newBuf := SecurePool.Get().(*SecureBuffer)
	copy(newBuf.Bytes(), key.key.Bytes())

	return newBuf, a.currentKey, nil
}

func (a *AuthSystem) ReturnKeyBuffer(buf *SecureBuffer) {
	buf.Clear()
	SecurePool.Put(buf)
}

func (a *AuthSystem) RotateKeys() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for id, key := range a.keys {
		if key.IsActive && now.After(key.Expiry) {
			key.Clear()
			key.IsActive = false
			a.audit("KEY_EXPIRED", "system", fmt.Sprintf("Key expired: %s", id))
		}
	}

	if a.currentKey != "" {
		if key, exists := a.keys[a.currentKey]; exists {
			if !key.IsActive || now.After(key.Expiry) {
				a.currentKey = ""
			}
		}
	}

	if a.currentKey == "" {
		var newestKey string
		var newestTime time.Time

		for id, key := range a.keys {
			if key.IsActive && key.CreatedAt.After(newestTime) {
				newestKey = id
				newestTime = key.CreatedAt
			}
		}

		if newestKey != "" {
			a.currentKey = newestKey
			a.audit("KEY_AUTO_SELECT", "system", fmt.Sprintf("New active key: %s", newestKey))
		}
	}
}

func (a *AuthSystem) audit(action, actor, message string) {
	entry := fmt.Sprintf("[%s] %s: %s - %s", time.Now().Format(time.RFC3339), action, actor, message)
	a.auditLog = append(a.auditLog, entry)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateKeyID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *AuthSystem) GetAuditLog(actor string) ([]string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	user, exists := a.users[actor]
	if !exists || user.Role != RoleAuditor || !user.IsActive {
		return nil, errors.New("access denied")
	}

	return a.auditLog, nil
}

func CleanupMemory(data []byte) {
	if len(data) == 0 {
		return
	}


	for i := range data {
		data[i] = 0
	}

	mem := unsafe.Slice((*byte)(unsafe.Pointer(&data[0])), len(data))
	for i := range mem {
		mem[i] = 0
	}
}

// --------------------------------------------
// Обработка файлов с авторизацией
// --------------------------------------------
func processFileWithAuth(auth *AuthSystem, token, inputPath, outputPath string, encrypt bool) error {
	username, err := auth.CheckSession(token)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	keyBuf, keyID, err := auth.GetActiveKey(username)
	if err != nil {
		return fmt.Errorf("key error: %w", err)
	}
	defer auth.ReturnKeyBuffer(keyBuf)

	key := keyBuf.Bytes()
	if len(key) != 32 {
		return errors.New("invalid key length")
	}

	if encrypt {
		return encryptFile(auth, username, keyID, key, inputPath, outputPath)
	} else {
		return decryptFile(auth, username, keyID, key, inputPath, outputPath)
	}
}

func encryptFile(auth *AuthSystem, username, keyID string, key []byte, inputPath, outputPath string) error {
	ivBuf := NewSecureBuffer(16)
	defer ivBuf.Clear()

	if _, err := rand.Read(ivBuf.Bytes()); err != nil {
		return err
	}

	block, err := NewKuznechik(key)
	if err != nil {
		return err
	}
	defer block.Clear()

	if err := processOFBFile(inputPath, outputPath, block, ivBuf.Bytes(), true); err != nil {
		return err
	}

	f, err := os.OpenFile(outputPath, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	if _, err := f.Write(ivBuf.Bytes()); err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		return err
	}

	auth.audit("FILE_ENCRYPT", username,
		fmt.Sprintf("File encrypted: %s -> %s (Key: %s)", inputPath, outputPath, keyID))

	return nil
}

func decryptFile(auth *AuthSystem, username, keyID string, key []byte, inputPath, outputPath string) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	iv := make([]byte, 16)
	if _, err := f.Read(iv); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp("", "decrypt_temp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, f); err != nil {
		return err
	}
	tmpFile.Close()

	block, err := NewKuznechik(key)
	if err != nil {
		return err
	}
	defer block.Clear()

	if err := processOFBFile(tmpFile.Name(), outputPath, block, iv, false); err != nil {
		return err
	}

	auth.audit("FILE_DECRYPT", username,
		fmt.Sprintf("File decrypted: %s -> %s (Key: %s)", inputPath, outputPath, keyID))

	return nil
}

func processOFBFile(inputPath, outputPath string, block cipher.Block, iv []byte, encrypt bool) error {
	inFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	stream := NewOFB(block, iv)
	buf := make([]byte, 64*1024)

	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		outBuf := make([]byte, n)
		stream.XORKeyStream(outBuf, buf[:n])

		if _, err := outFile.Write(outBuf); err != nil {
			return err
		}

		CleanupMemory(buf[:n])
		CleanupMemory(outBuf)
	}

	CleanupMemory(iv)
	return nil
}

// --------------------------------------------
// Тестирование производительности
// --------------------------------------------
func testFileSizes(auth *AuthSystem, token string) {
	sizes := []struct {
		size int64
		name string
	}{
		{1 << 20, "1MB"},
		{100 << 20, "100MB"},
		{1000 << 20, "1000MB"},
	}

	for _, s := range sizes {
		inputFile := fmt.Sprintf("test_%s.bin", s.name)
		outputFile := fmt.Sprintf("encrypted_%s.bin", s.name)
		decryptedFile := fmt.Sprintf("decrypted_%s.bin", s.name)

		generateTestFile(inputFile, s.size)

		start := time.Now()
		if err := processFileWithAuth(auth, token, inputFile, outputFile, true); err != nil {
			fmt.Printf("Encryption error: %v\n", err)
			return
		}
		encTime := time.Since(start)

		start = time.Now()
		if err := processFileWithAuth(auth, token, outputFile, decryptedFile, false); err != nil {
			fmt.Printf("Decryption error: %v\n", err)
			return
		}
		decTime := time.Since(start)

		if !filesEqual(inputFile, decryptedFile) {
			fmt.Printf("File corruption detected: %s\n", s.name)
			return
		}

		fmt.Printf("File size: %s\n", s.name)
		fmt.Printf("Encryption time: %v (%.2f MB/s)\n", encTime, float64(s.size)/encTime.Seconds()/(1<<20))
		fmt.Printf("Decryption time: %v (%.2f MB/s)\n", decTime, float64(s.size)/decTime.Seconds()/(1<<20))
		fmt.Println("----------------------------------------")
	}
}

func generateTestFile(path string, size int64) {
	file, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	if _, err := io.CopyN(file, rand.Reader, size); err != nil {
		panic(err)
	}
}

func filesEqual(file1, file2 string) bool {
	f1, err := os.Open(file1)
	if err != nil {
		return false
	}
	defer f1.Close()

	f2, err := os.Open(file2)
	if err != nil {
		return false
	}
	defer f2.Close()

	const chunkSize = 64 * 1024
	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	for {
		n1, err1 := f1.Read(buf1)
		n2, err2 := f2.Read(buf2)

		if err1 != nil || err2 != nil {
			return err1 == io.EOF && err2 == io.EOF
		}

		if n1 != n2 {
			return false
		}

		for i := 0; i < n1; i++ {
			if buf1[i] != buf2[i] {
				return false
			}
		}
	}
}

func testKeyChange(auth *AuthSystem, token string, blockCount, keyChangeInterval int) {
	data := make([]byte, blockCount*16)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}

	segmentSize := keyChangeInterval * 16
	segmentCount := (blockCount + keyChangeInterval - 1) / keyChangeInterval
	keys := make([][]byte, segmentCount)
	ivs := make([][]byte, segmentCount)

	for i := range keys {
		keyBuf := make([]byte, 32)
		rand.Read(keyBuf)
		keys[i] = keyBuf

		ivBuf := make([]byte, 16)
		rand.Read(ivBuf)
		ivs[i] = ivBuf
	}

	encrypted := make([]byte, len(data))
	startEnc := time.Now()
	for i := 0; i < segmentCount; i++ {
		start := i * segmentSize
		end := start + segmentSize
		if end > len(data) {
			end = len(data)
		}

		block, err := NewKuznechik(keys[i])
		if err != nil {
			panic(err)
		}
		stream := NewOFB(block, ivs[i])
		stream.XORKeyStream(encrypted[start:end], data[start:end])
		block.Clear()
	}
	encTime := time.Since(startEnc)

	decrypted := make([]byte, len(data))
	startDec := time.Now()
	for i := 0; i < segmentCount; i++ {
		start := i * segmentSize
		end := start + segmentSize
		if end > len(encrypted) {
			end = len(encrypted)
		}

		block, err := NewKuznechik(keys[i])
		if err != nil {
			panic(err)
		}
		stream := NewOFB(block, ivs[i])
		stream.XORKeyStream(decrypted[start:end], encrypted[start:end])
		block.Clear()
	}
	decTime := time.Since(startDec)

	if !equal(data, decrypted) {
		panic("data corruption detected")
	}

	auth.audit("KEYCHANGE_TEST", "system",
		fmt.Sprintf("Blocks: %d, Interval: %d", blockCount, keyChangeInterval))

	fmt.Printf("Blocks: %d, Key change interval: %d\n", blockCount, keyChangeInterval)
	fmt.Printf("Encryption time: %v (%.2f MB/s)\n",
		encTime, float64(len(data))/encTime.Seconds()/(1<<20))
	fmt.Printf("Decryption time: %v (%.2f MB/s)\n",
		decTime, float64(len(data))/decTime.Seconds()/(1<<20))
	fmt.Println("----------------------------------------")
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --------------------------------------------
// Главная функция
// --------------------------------------------
func main() {
	auth := NewAuthSystem()

	// Запуск фоновой ротации ключей
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			auth.RotateKeys()
		}
	}()

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("СКЗИ КС3: Система шифрования 'Кузнечик'")
	fmt.Println("Команды: login, create_user, create_key, encrypt, decrypt, test_files, test_keychange, audit_log, exit")

	var currentToken string

	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		parts := strings.Fields(input)

		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "login":
			if len(parts) < 3 {
				fmt.Println("Использование: login <логин> <пароль>")
				continue
			}
			token, err := auth.Login(parts[1], parts[2])
			if err != nil {
				fmt.Println("Ошибка входа:", err)
			} else {
				currentToken = token
				fmt.Println("Успешный вход. Токен сохранен.")
			}

		case "create_user":
			if len(parts) < 5 {
				fmt.Println("Использование: create_user <логин> <пароль> <роль(admin|operator|auditor)>")
				continue
			}
			_, err := auth.CheckSession(currentToken)
			if err != nil {
				fmt.Println("Ошибка: требуется аутентификация")
				continue
			}
			err = auth.CreateUser("admin", parts[1], parts[2], parts[3])
			if err != nil {
				fmt.Println("Ошибка:", err)
			} else {
				fmt.Println("Пользователь создан")
			}

		case "create_key":
			if len(parts) < 2 {
				fmt.Println("Использование: create_key <срок_действия_в_днях>")
				continue
			}
			username, err := auth.CheckSession(currentToken)
			if err != nil {
				fmt.Println("Ошибка: требуется аутентификация")
				continue
			}
			var days float64
			if _, err := fmt.Sscanf(parts[1], "%f", &days); err != nil {
				fmt.Println("Неверный формат числа")
				continue
			}
			keyID, err := auth.CreateKey(username, time.Hour*24*time.Duration(days))
			if err != nil {
				fmt.Println("Ошибка:", err)
			} else {
				fmt.Println("Ключ создан:", keyID)
			}

		case "encrypt":
			if len(parts) < 3 {
				fmt.Println("Использование: encrypt <входной_файл> <выходной_файл>")
				continue
			}
			err := processFileWithAuth(auth, currentToken, parts[1], parts[2], true)
			if err != nil {
				fmt.Println("Ошибка шифрования:", err)
			} else {
				fmt.Println("Файл успешно зашифрован")
			}

		case "decrypt":
			if len(parts) < 3 {
				fmt.Println("Использование: decrypt <входной_файл> <выходной_файл>")
				continue
			}
			err := processFileWithAuth(auth, currentToken, parts[1], parts[2], false)
			if err != nil {
				fmt.Println("Ошибка расшифрования:", err)
			} else {
				fmt.Println("Файл успешно расшифрован")
			}

		case "test_files":
			_, err := auth.CheckSession(currentToken)
			if err != nil {
				fmt.Println("Ошибка: требуется аутентификация")
				continue
			}
			fmt.Println("Тестирование на файлах разных размеров...")
			testFileSizes(auth, currentToken)

		case "test_keychange":
			if len(parts) < 3 {
				fmt.Println("Использование: test_keychange <количество_блоков> <интервал_смены>")
				continue
			}
			_, err := auth.CheckSession(currentToken)
			if err != nil {
				fmt.Println("Ошибка: требуется аутентификация")
				continue
			}
			var blockCount, interval int
			if _, err := fmt.Sscanf(parts[1], "%d", &blockCount); err != nil {
				fmt.Println("Неверный формат числа блоков")
				continue
			}
			if _, err := fmt.Sscanf(parts[2], "%d", &interval); err != nil {
				fmt.Println("Неверный формат интервала")
				continue
			}
			testKeyChange(auth, currentToken, blockCount, interval)

		case "audit_log":
			logs, err := auth.GetAuditLog(currentToken)
			if err != nil {
				fmt.Println("Ошибка:", err)
			} else {
				fmt.Println("Журнал аудита:")
				for _, entry := range logs {
					fmt.Println(entry)
				}
			}
		case "exit":
			fmt.Println("Выход из системы")
			return

		default:
			fmt.Println("Неизвестная команда:", parts[0])
			fmt.Println("Доступные команды: login, create_user, create_key, encrypt, decrypt, test_files, test_keychange, audit_log, exit")
		}
	}
}
