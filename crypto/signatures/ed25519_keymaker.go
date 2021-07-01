package signatures

//
//type ed25519KeyMaker struct{}
//
//func (e *ed25519KeyMaker) NewKey(seed crypto.Seed) Key {
//	return newEd25519Key(seed)
//}
//
//func (e *ed25519KeyMaker) Marshal(key Key) ([]byte, error) {
//	panic("implement me")
//}
//
//func (e *ed25519KeyMaker) Unmarshal(bytes []byte) (Key, error) {
//	panic("implement me")
//}
//
//func Ed25519KeyMaker() KeyMaker {
//	return &ed25519KeyMaker{}
//}
//
//// represents the payload of the key, and the type of key
//// used to add additional data to the marshaled key.
//type almostMarshaledKey struct {
//	marshaledKey     []byte
//	marshaledKeyType uint64
//}
