package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// alertcast verify — звірка з живим ukrainealarm: один запит до /api/v3/alerts і порівняння з
// тим, що alertcast віддає через сумісний /api/v3/alerts (для всіх регіонів). Збіг означає,
// що дані alertd актуальні, а ієрархія (які регіони стосуються яких тривог) — та сама, що в
// ukrainealarm. Токен ukrainealarm береться з UA_TOKEN або з налаштувань alertd.

// flexStr — regionId може прийти рядком або числом.
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexStr(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexStr(n.String())
	return nil
}

type cmpRecord struct {
	RegionID     flexStr `json:"regionId"`
	RegionName   string  `json:"regionName"`
	ActiveAlerts []struct {
		RegionID flexStr `json:"regionId"`
		Type     string  `json:"type"`
		Levels   []Level `json:"activeAlertLevels"`
	} `json:"activeAlerts"`
}

// alertSet — регіон запису → множина «регіон тривоги|тип|рівні».
func alertSet(recs []cmpRecord) (map[string]map[string]bool, map[string]string) {
	out, names := map[string]map[string]bool{}, map[string]string{}
	for _, r := range recs {
		id := string(r.RegionID)
		names[id] = r.RegionName
		for _, a := range r.ActiveAlerts {
			lv := map[string]bool{}
			addLevels(lv, a.Levels)
			k := string(a.RegionID) + "|" + a.Type + "|" + strings.Join(sortedLevels(lv), "+")
			if out[id] == nil {
				out[id] = map[string]bool{}
			}
			out[id][k] = true
		}
	}
	return out, names
}

type diff struct {
	Region, Name string
	Missing      []string // є в ukrainealarm, немає в alertcast
	Extra        []string // є в alertcast, немає в ukrainealarm
}

func compareSets(up, our map[string]map[string]bool, names map[string]string) []diff {
	ids := map[string]bool{}
	for id := range up {
		ids[id] = true
	}
	for id := range our {
		ids[id] = true
	}
	var out []diff
	for id := range ids {
		d := diff{Region: id, Name: names[id]}
		for k := range up[id] {
			if !our[id][k] {
				d.Missing = append(d.Missing, k)
			}
		}
		for k := range our[id] {
			if !up[id][k] {
				d.Extra = append(d.Extra, k)
			}
		}
		if len(d.Missing)+len(d.Extra) > 0 {
			sort.Strings(d.Missing)
			sort.Strings(d.Extra)
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return idLess(out[i].Region, out[j].Region) })
	return out
}

func countAlerts(m map[string]map[string]bool) (records, alerts int) {
	seen := map[string]bool{}
	for _, s := range m {
		for k := range s {
			seen[k] = true
		}
	}
	return len(m), len(seen)
}

var waitSecRe = regexp.MustCompile(`(?i)wait\s+(\d+)\s+second`)

func fetchUpstream(base, token string) ([]cmpRecord, error) {
	hc := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequest("GET", strings.TrimRight(base, "/")+"/api/v3/alerts", nil)
		req.Header.Set("Authorization", token)
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode == 429 {
			wait := 61
			if m := waitSecRe.FindSubmatch(body); m != nil {
				wait, _ = strconv.Atoi(string(m[1]))
				wait++
			}
			fmt.Printf("  ліміт API ukrainealarm (alertd щойно опитував) — чекаю %d с…\n", wait)
			time.Sleep(time.Duration(wait) * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("ukrainealarm: HTTP %d", resp.StatusCode)
		}
		if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
			return nil, errors.New("ukrainealarm: відповідь не є списком")
		}
		var recs []cmpRecord
		if err := json.Unmarshal(body, &recs); err != nil {
			return nil, fmt.Errorf("ukrainealarm: %v", err)
		}
		return recs, nil
	}
	return nil, errors.New("ukrainealarm: ліміт запитів не відпускає")
}

func fetchOurs(local string) ([]cmpRecord, error) {
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + local + "/v3/alerts")
	if err != nil {
		return nil, fmt.Errorf("служба alertcast не відповідає на %s: %v", local, err)
	}
	defer resp.Body.Close()
	var recs []cmpRecord
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&recs); err != nil {
		return nil, err
	}
	return recs, nil
}

func verifyCmd(cfg Config) int {
	token := os.Getenv("UA_TOKEN")
	if token == "" {
		_ = loadEnvFile(env("ALERTD_ENV_FILE", "/etc/alertd/alertd.env"))
		token = os.Getenv("UA_TOKEN")
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "помилка: потрібен токен ukrainealarm — UA_TOKEN або /etc/alertd/alertd.env (через sudo)")
		return 2
	}
	base := env("UA_API_BASE", "https://api.ukrainealarm.com")
	fmt.Println("Звірка з ukrainealarm (1 запит до API; alertd може пропустити одне своє опитування)…")
	up, err := fetchUpstream(base, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		return 1
	}
	upSet, names := alertSet(up)
	var diffs []diff
	// webhook і знімки доходять із затримкою — якщо щойно щось змінилось, даємо alertd до ~70 с
	for attempt := 0; ; attempt++ {
		ours, err := fetchOurs(cfg.LocalListen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "помилка:", err)
			return 1
		}
		ourSet, ourNames := alertSet(ours)
		for k, v := range ourNames {
			if names[k] == "" {
				names[k] = v
			}
		}
		diffs = compareSets(upSet, ourSet, names)
		if len(diffs) == 0 || attempt == 7 {
			break
		}
		if attempt == 0 {
			fmt.Printf("  є розбіжності (%d регіонів) — можливо, зміна ще в дорозі; перевіряю ще раз протягом ~70 с…\n", len(diffs))
		}
		time.Sleep(10 * time.Second)
	}
	recs, alerts := countAlerts(upSet)
	if len(diffs) == 0 {
		fmt.Printf("✓ збігається: %d регіонів зачеплено, %d тривог (регіон+тип+рівні)\n", recs, alerts)
		return 0
	}
	fmt.Printf("✗ розбіжності в %d регіонах (ukrainealarm: %d регіонів, %d тривог):\n", len(diffs), recs, alerts)
	for i, d := range diffs {
		if i == 30 {
			fmt.Printf("  … ще %d\n", len(diffs)-30)
			break
		}
		fmt.Printf("  %s %s\n", d.Region, d.Name)
		for _, m := range d.Missing {
			fmt.Printf("      лише в ukrainealarm: %s\n", m)
		}
		for _, x := range d.Extra {
			fmt.Printf("      лише в alertcast:    %s\n", x)
		}
	}
	return 1
}
