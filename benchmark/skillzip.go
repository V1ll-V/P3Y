package benchmark

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"path"
	"strings"
)

const (
	maxSkillZipSize   = 16 << 20
	maxSkillEntries   = 256
	maxSingleDocBytes = 128 * 1024
	maxSkillPromptLen = 18000
)

type SkillPackage struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	Instructions string   `json:"instructions"`
	Files        []string `json:"files"`
}

// ParseSkillZip safely reads an uploaded *-agent-skill.zip archive in memory,
// extracting SKILL.md and key reference guides (agent-play.md, safety.md) for
// planner/worker prompt injection without executing or writing untrusted paths.
func ParseSkillZip(raw []byte) (*SkillPackage, error) {
	if len(raw) == 0 {
		return nil, errors.New("Skill 包为空")
	}
	if len(raw) > maxSkillZipSize {
		return nil, errors.New("Skill 包大小超过 16 MiB 上限")
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, errors.New("无效的 zip 文件：" + err.Error())
	}
	if len(zr.File) > maxSkillEntries {
		return nil, errors.New("Skill 包文件数量超过限制")
	}

	var (
		skillMD      string
		agentPlayMD  string
		safetyMD     string
		otherRefList []string
		fileList     []string
	)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		clean := path.Clean(strings.ReplaceAll(f.Name, "\\", "/"))
		if clean == "." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			continue
		}
		fileList = append(fileList, clean)
		lower := strings.ToLower(clean)
		if !strings.HasSuffix(lower, ".md") {
			continue
		}
		base := path.Base(lower)
		switch {
		case base == "skill.md":
			skillMD = readZipText(f, maxSingleDocBytes)
		case base == "agent-play.md":
			agentPlayMD = readZipText(f, maxSingleDocBytes)
		case base == "safety.md":
			safetyMD = readZipText(f, maxSingleDocBytes)
		default:
			otherRefList = append(otherRefList, clean)
		}
	}
	if strings.TrimSpace(skillMD) == "" {
		return nil, errors.New("Skill 包中未找到 SKILL.md")
	}

	name, desc := parseFrontmatter(skillMD)
	if name == "" {
		name = "custom-platform-skill"
	}

	var b strings.Builder
	b.WriteString(strings.TrimSpace(skillMD))
	if strings.TrimSpace(agentPlayMD) != "" {
		b.WriteString("\n\n---\n\n")
		b.WriteString(strings.TrimSpace(agentPlayMD))
	}
	if strings.TrimSpace(safetyMD) != "" {
		b.WriteString("\n\n---\n\n")
		b.WriteString(strings.TrimSpace(safetyMD))
	}
	instructions := b.String()
	if len(instructions) > maxSkillPromptLen {
		instructions = instructions[:maxSkillPromptLen] + "\n...(Skill 文档已截断)"
	}

	return &SkillPackage{
		Name:         name,
		Description:  desc,
		Instructions: instructions,
		Files:        fileList,
	}, nil
}

func readZipText(f *zip.File, limit int64) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return ""
	}
	return string(data)
}

func parseFrontmatter(md string) (name, desc string) {
	lines := strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n")
	if len(lines) < 3 || strings.TrimSpace(lines[0]) != "---" {
		return "", ""
	}
	for _, ln := range lines[1:] {
		trim := strings.TrimSpace(ln)
		if trim == "---" {
			break
		}
		if strings.HasPrefix(trim, "name:") {
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trim, "name:")), `"'`)
		} else if strings.HasPrefix(trim, "description:") {
			desc = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trim, "description:")), `"'`)
		}
	}
	return name, desc
}
