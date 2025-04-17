package vpack

type voteField uint8

const (
	credField voteField = iota
	pfField
	rField
	perField
	propField
	digField
	encdigField
	operField
	opropField
	rndField
	sndField
	stepField
	sigField
	pField
	p1sField
	p2Field
	p2sField
	psField
	sField
)

const (
	msgpMapMarker0  = "\x80"       // Map with 0 items
	msgpMapMarker1  = "\x81"       // Map with 1 items
	msgpMapMarker2  = "\x82"       // Map with 2 items
	msgpMapMarker3  = "\x83"       // Map with 3 items
	msgpMapMarker4  = "\x84"       // Map with 4 items
	msgpMapMarker5  = "\x85"       // Map with 5 items
	msgpMapMarker6  = "\x86"       // Map with 6 items
	msgpCredField   = "\xa4cred"   // "cred" field
	msgpPfField     = "\xa2pf"     // "pf" field
	msgpRField      = "\xa1r"      // "r" field
	msgpPerField    = "\xa3per"    // "per" field
	msgpPropField   = "\xa4prop"   // "prop" field
	msgpDigField    = "\xa3dig"    // "dig" field
	msgpEncdigField = "\xa6encdig" // "encdig" field
	msgpOperField   = "\xa4oper"   // "oper" field
	msgpOpropField  = "\xa5oprop"  // "oprop" field
	msgpRndField    = "\xa3rnd"    // "rnd" field
	msgpSndField    = "\xa3snd"    // "snd" field
	msgpStepField   = "\xa4step"   // "step" field
	msgpSigField    = "\xa3sig"    // "sig" field
	msgpPField      = "\xa1p"      // "p" field
	msgpP1sField    = "\xa3p1s"    // "p1s" field
	msgpP2Field     = "\xa2p2"     // "p2" field
	msgpP2sField    = "\xa3p2s"    // "p2s" field
	msgpPsField     = "\xa2ps"     // "ps" field
	msgpSField      = "\xa1s"      // "s" field
)
