package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	redirectIPV4 = "192.168.0.40"            // For A records (IPv4)
	redirectIPV6 = "2a02:8071:d81:340::7e2a" // For AAAA records (IPv6)
)

func handleARecord(msg *dns.Msg, q dns.Question) {
	aRecord := dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    600,
		},
		A: net.ParseIP(redirectIPV4),
	}
	msg.Answer = append(msg.Answer, &aRecord)
}

func handleAAAARecord(msg *dns.Msg, q dns.Question) {
	aaaaRecord := dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    600,
		},
		AAAA: net.ParseIP(redirectIPV6),
	}
	msg.Answer = append(msg.Answer, &aaaaRecord)
}

//////////////////////////////////////

var (
	AllowedDomains = make(map[string]bool)
	RecentBlocked  = []string{}
	mu             sync.RWMutex
)

func ExtractBaseDomain(inputURL string) string {
	return inputURL
}

/*
	func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			fmt.Printf("Received DNS query for %s 			[%s]\n", q.Name, dns.TypeToString[q.Qtype])

			mu.RLock()
			allowed := false // AllowedDomains[ExtractBaseDomain(q.Name)]
			mu.RUnlock()

			if allowed || (!strings.Contains(q.Name, "dbs") && !strings.Contains(q.Name, "apple_QWECCQEB") && !strings.Contains(q.Name, "bsweinheim") && !strings.Contains(q.Name, "jamfcloud")) {
				c := new(dns.Client)
				res, _, err := c.Exchange(r, "8.8.8.8:53")
				if err != nil {
					fmt.Printf("Error resolving DNS query: %s\n", err)
					continue
				}

				for _, ans := range res.Answer {
					m.Answer = append(m.Answer, ans)
				}
			} else {
				mu.RLock()
				RecentBlocked = append(RecentBlocked, q.Name)
				if len(RecentBlocked) > 30 {
					RecentBlocked = RecentBlocked[1:]
				}
				mu.RUnlock()
				fmt.Printf("Disallow %s \n", q.Name)
				m.SetRcode(r, dns.RcodeRefused)
			}
		}

		w.WriteMsg(m)
	}
*/
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	// Handle each DNS question in the request
	for _, q := range r.Question {
		fmt.Printf("Received DNS query for %s 			[%s]\n", q.Name, dns.TypeToString[q.Qtype])
		if strings.Contains(q.Name, "dbs") || strings.Contains(q.Name, "apple") || strings.Contains(q.Name, "bsweinheim") || strings.Contains(q.Name, "jamfcloud") {
			c := new(dns.Client)
			res, _, err := c.Exchange(r, "8.8.8.8:53")
			if err != nil {
				fmt.Printf("Error resolving DNS query: %s\n", err)
				continue
			}

			for _, ans := range res.Answer {
				msg.Answer = append(msg.Answer, ans)
			}
		} else {
			switch q.Qtype {
			case dns.TypeA:
				handleARecord(&msg, q)
			case dns.TypeAAAA:
				handleAAAARecord(&msg, q)
			default:
				log.Printf("Unhandled DNS query type: %d\n", q.Qtype)
			}
		}
	}

	// Send the response back to the client
	if err := w.WriteMsg(&msg); err != nil {
		log.Printf("Failed to send DNS response: %s\n", err.Error())
	}
}

func handleDNSControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" || r.Method == "GET" {
		r.ParseForm()
		baseDomain := r.Form.Get("base_domain")
		action := r.Form.Get("action")
		fmt.Printf("%s,%s\n", baseDomain, action)

		mu.Lock()
		defer mu.Unlock()
		if action == "allow" {
			AllowedDomains[baseDomain] = true
			RecentBlocked = removeString(RecentBlocked, baseDomain)
		} else if action == "disallow" {
			delete(AllowedDomains, baseDomain)
		}
	}
	//fmt.Println(AllowedDomains)
	http.Redirect(w, r, "/control", http.StatusSeeOther)
}

func handleControlPanel(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("cp:", AllowedDomains)
	mu.RLock()
	defer mu.RUnlock()

	fmt.Fprintf(w, "<h1>Allowed Base Domains</h1>")
	fmt.Fprintf(w, "<ul>")
	for domain := range AllowedDomains {
		fmt.Fprintf(w, "<li>%s <a href=\"/controla?base_domain=%s&action=disallow\">Remove</a></li>", domain, domain)
	}
	fmt.Fprintf(w, "</ul>")

	fmt.Fprintf(w, "<form method=\"post\" action=\"/controla\">")
	fmt.Fprintf(w, "<input type=\"text\" name=\"base_domain\" placeholder=\"Enter base domain\">")
	fmt.Fprintf(w, "<input type=\"submit\" name=\"action\" value=\"allow\">")
	fmt.Fprintf(w, "</form>")
	for _, domain := range RecentBlocked {
		fmt.Fprintf(w, "<li>%s <a href=\"/controla?base_domain=%s&action=allow\">Allow</a></li>", domain, domain)
	}
}

func main() {
	server := &dns.Server{Addr: ":53", Net: "udp"}
	dns.HandleFunc(".", handleDNSRequest)

	http.HandleFunc("/control", handleControlPanel)
	http.HandleFunc("/controla", handleDNSControl)

	fmt.Println("Control panel server listening on port 8080...")
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start control panel server: %s\n", err)
			os.Exit(1)
		}
	}()

	fmt.Println("DNS server listening on port 53...")
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start DNS server: %s\n", err)
		os.Exit(1)
	}
}

func removeString(slice []string, str string) []string {
	var result []string
	for _, s := range slice {
		if s != str {
			result = append(result, s)
		}
	}
	return result
}
