package acmewrapper

import "github.com/xenolf/lego/acme"

// wrapperChallengeProvider is used to fit into the acme.ChallengeProvider interface,
// which allows us to modify our server during runtime to solve the SNI challenge
type wrapperChallengeProvider struct {
	w               *AcmeWrapper
	challengeDomain string
}

// Present sets up the challenge domain thru SNI. Part of acme.ChallengeProvider interface
func (c *wrapperChallengeProvider) Present(domain, token, keyAuth string) error {
	logf("[acmewrapper] Started SNI server modification for %s", domain)

	// Use ACME's SNI challenge cert maker. How nice that it is exported :)
	_, err := acme.TLSALPNChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}

	c.challengeDomain = domain
	return nil

}

// CleanUp removes the challenge domain from SNI. Part of acme.ChallengeProvider interface
func (c *wrapperChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	logf("[acmewrapper] End of SNI server modification for %s\n", domain)
	c.w.RemSNI(c.challengeDomain)
	return nil
}
