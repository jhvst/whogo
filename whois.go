package whogo

import (
	"bufio"
	"bytes"
	"github.com/ziutek/telnet"
	"io/ioutil"
	"time"
)

// Feed this function with data from Whois() function and it will tell whether the domain is available.
func Available(data []byte) bool {
	available := [34]string{"No Data Found", "NOT FOUND", "Domain Status: Available", "not registred,", "No match", "This query returned 0 objects", "Domain Not Found", "nothing found", "No records matching", "Status: AVAILABLE", "does not exist in database", "Status: Not Registered", "No match for", "Object does not exist", "We do not have an entry in our database matching your query", "no existe", "no matching record", "No domain records were found to match", "No entries found", "Status: free", "No entries found for the selected sourc", "not found...", "The domain has not been registered", "Not Registered", "No data was found", "This domain is available for registration", "Nothing found for this query", "No such domain", "No Objects Found", "Object_Not_Found", "No information available", "Domain is not registered", "domain name not known", "not found in database"}
	for _, v := range available {
		if v == string(data) {
			return true
		}
	}
	return false
}

func Solve(domain string, timeout time.Duration) (string, error) {
	conn, err := Dial("whois.iana.org", timeout)
	if err != nil {
		return "", err
	}
	err = Send(conn, domain, timeout)
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

func Dial(host string, timeout time.Duration) (*telnet.Conn, error) {
	conn, err := telnet.DialTimeout("tcp", host+":43", timeout)
	if err != nil {
		return conn, err
	}
	conn.SetUnixWriteMode(true)
	return conn, nil
}

func Send(conn *telnet.Conn, s string, timeout time.Duration) error {
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

// Takes in domain as a string without the any prefix. Example: google.com
// Timeout defines timeout which is set at every write and read request.
// Returns byte array of the WHOIS query.
func Whois(domain string, timeout time.Duration) ([]byte, error) {
	refer, err := Solve(domain, timeout)
	if err != nil {
		return nil, err
	}
	conn, err := Dial(refer, timeout)
	if err != nil {
		return nil, err
	}
	err = Send(conn, domain, timeout)
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

//TODO: parse whois records and return Go struct
// func Records(status []byte) {
// 	lines := bytes.Split(status, []byte("\n"))
// 	for _, line := range lines {
// 		fmt.Println(string(line))
// 	}
// }
