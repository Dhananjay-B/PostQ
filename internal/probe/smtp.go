package probe

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	smtpmodels "github.com/Dhananjay-B/PostQ/internal/model/smtpmodels"
)

func ScanSMTP(target smtpmodels.SMTPTarget) (probeResponse smtpmodels.SMTPProbe, err error) {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target.HostName, target.Port), 5*time.Second)
	if err != nil {
		return probeResponse, fmt.Errorf("smtp connection failed: %w", err)
	}
	defer connection.Close()

	reader := bufio.NewReader(connection)

	banner, err := reader.ReadString('\n')
	if err != nil {
		return probeResponse, fmt.Errorf("failed to read SMTP banner: %w", err)
	}
	banner = strings.TrimSpace(banner)
	bannerFields := strings.Split(banner, " ")
	if len(bannerFields) >= 4 {
		probeResponse.ServerHostName = bannerFields[1]

		if strings.Contains(bannerFields[2], "ESMTP") {
			probeResponse.ESMPTSupported = true
		}
		probeResponse.SMTPSoftware = strings.Join(bannerFields[3:], "")
	}

	return probeResponse, nil
}
