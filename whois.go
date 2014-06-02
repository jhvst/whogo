package whogo

import (
	"bufio"
	"bytes"
	"github.com/9uuso/go-jaro-winkler-distance"
	"github.com/ziutek/telnet"
	"io/ioutil"
	"strings"
	"time"
)

type record struct {
	Nameservers []string
	Status      []string
	Created     string
	Updated     string
	Expiration  string
	Referral    string
}

// Available tells whether a domain is available according to it's WHOIS query.
// The parameter should be the result from Whois function.
func Available(data []byte) bool {
	available := [34]string{"No Data Found", "NOT FOUND", "Domain Status: Available", "not registred,", "No match", "This query returned 0 objects", "Domain Not Found", "nothing found", "No records matching", "Status: AVAILABLE", "does not exist in database", "Status: Not Registered", "No match for", "Object does not exist", "We do not have an entry in our database matching your query", "no existe", "no matching record", "No domain records were found to match", "No entries found", "Status: free", "No entries found for the selected sourc", "not found...", "The domain has not been registered", "Not Registered", "No data was found", "This domain is available for registration", "Nothing found for this query", "No such domain", "No Objects Found", "Object_Not_Found", "No information available", "Domain is not registered", "domain name not known", "not found in database"}
	for _, v := range available {
		if v == string(data) {
			return true
		}
	}
	return false
}

func solve(domain string, timeout time.Duration) (string, error) {
	conn, err := dial("whois.iana.org", timeout)
	if err != nil {
		return "", err
	}
	err = send(conn, domain, timeout)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), []byte("refer")) {
			refer := bytes.Split(scanner.Bytes(), []byte(":"))[1]
			return string(bytes.TrimSpace(refer)), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

func dial(host string, timeout time.Duration) (*telnet.Conn, error) {
	conn, err := telnet.DialTimeout("tcp", host+":43", timeout)
	if err != nil {
		return conn, err
	}
	conn.SetUnixWriteMode(true)
	return conn, nil
}

func send(conn *telnet.Conn, s string, timeout time.Duration) error {
	conn.SetWriteDeadline(time.Now().Add(timeout))
	buf := make([]byte, len(s)+1)
	copy(buf, s)
	buf[len(s)] = '\n'
	_, err := conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

// Whois returns WHOIS query of a domain in format such as google.com
// Timeout defines timeout which is set at every write and read request.
func Whois(domain string, timeout time.Duration) ([]byte, error) {
	refer, err := solve(domain, timeout)
	if err != nil {
		return nil, err
	}
	conn, err := dial(refer, timeout)
	if err != nil {
		return nil, err
	}
	err = send(conn, domain, timeout)
	if err != nil {
		return nil, err
	}
	whois, err := ioutil.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	//TODO: automatically search for the exact domain when whois returns
	//more than one record.
	// if bytes.Contains(whois, []byte("To single out one record")) {
	// 	fmt.Println("Contains more than one record.")
	// 	err = Send(conn, domain, timeout)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	whois, err = ioutil.ReadAll(conn)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }
	conn.Close()
	return bytes.TrimSpace(whois), nil
}

func find(query map[string]string, s ...string) string {

	var max = float64(0)
	var res string

	if len(s) == 1 {
		for whoisIndex, whoisValue := range query {
			score := jwd.Calculate(whoisIndex, s[0])
			if score > max && score > 0.7 {
				max = score
				res = whoisValue
			}
		}
	}

	return res
}

// Records uses Jaro-Winkler distance to parse WHOIS queries.
// Other than .com domains may not be supported.
func Records(data []byte) record {
	lines := bytes.Split(data, []byte("\n"))
	query := make(map[string]string)
	var record record
	for _, line := range lines {
		if jwd.Calculate(strings.Split(string(line), ":")[0], "Referral") > 0.7 && bytes.Contains(line, []byte(":")) {
			record.Referral = strings.TrimSpace(strings.Split(string(line), ": ")[1])
		}
		if len(line) > 0 && bytes.Contains(line, []byte(":")) && len(bytes.TrimSpace(bytes.Split(line, []byte(":"))[1])) > 0 {
			this := string(line)
			if len(query[strings.TrimSpace(strings.Split(this, ":")[0])]) != 0 {
				n := query[strings.TrimSpace(strings.Split(this, ":")[0])]
				query[strings.TrimSpace(strings.Split(this, ":")[0])] = n + "," + strings.TrimSpace(strings.Split(this, ":")[1])
			} else {
				query[strings.TrimSpace(strings.Split(this, ":")[0])] = strings.TrimSpace(strings.Split(this, ":")[1])
			}
		}
	}
	record.Updated = find(query, "Updated")
	record.Created = find(query, "Created")
	record.Nameservers = strings.Split(find(query, "Nameservers"), ",")
	record.Status = strings.Split(find(query, "Status"), ",")
	record.Expiration = find(query, "Expiration")
	return record
}
