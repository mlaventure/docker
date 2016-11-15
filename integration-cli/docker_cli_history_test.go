package main

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/go-check/check"
)

func (s *DockerSuite) TestHistoryExistentImage(c *check.C) {
	dockerCmd(c, "history", "busybox")
}

func (s *DockerSuite) TestHistoryNonExistentImage(c *check.C) {
	_, _, err := dockerCmdWithError("history", "testHistoryNonExistentImage")
	c.Assert(err, checker.NotNil, check.Commentf("history on a non-existent image should fail."))
}

func (s *DockerSuite) TestHistoryImageWithComment(c *check.C) {
	name := "testhistoryimagewithcomment"

	// make an image through docker commit <container id> [ -m messages ]

	dockerCmd(c, "run", "--name", name, "busybox", "true")
	dockerCmd(c, "wait", name)

	comment := "This_is_a_comment"
	dockerCmd(c, "commit", "-m="+comment, name, name)

	// test docker history <image id> to check comment messages

	out, _ := dockerCmd(c, "history", name)
	outputTabs := strings.Fields(strings.Split(out, "\n")[1])
	actualValue := outputTabs[len(outputTabs)-1]
	c.Assert(actualValue, checker.Contains, comment)
}

func (s *DockerSuite) TestHistoryHumanOptionFalse(c *check.C) {
	out, _ := dockerCmd(c, "history", "--human=false", "busybox")
	lines := strings.Split(out, "\n")
	sizeColumnRegex, _ := regexp.Compile("SIZE +")
	indices := sizeColumnRegex.FindStringIndex(lines[0])
	startIndex := indices[0]
	endIndex := indices[1]
	for i := 1; i < len(lines)-1; i++ {
		if endIndex > len(lines[i]) {
			endIndex = len(lines[i])
		}
		sizeString := lines[i][startIndex:endIndex]

		_, err := strconv.Atoi(strings.TrimSpace(sizeString))
		c.Assert(err, checker.IsNil, check.Commentf("The size '%s' was not an Integer", sizeString))
	}
}

func (s *DockerSuite) TestHistoryHumanOptionTrue(c *check.C) {
	out, _ := dockerCmd(c, "history", "--human=true", "busybox")
	lines := strings.Split(out, "\n")
	sizeColumnRegex, _ := regexp.Compile("SIZE +")
	humanSizeRegexRaw := "\\d+.*B" // Matches human sizes like 10 MB, 3.2 KB, etc
	indices := sizeColumnRegex.FindStringIndex(lines[0])
	startIndex := indices[0]
	endIndex := indices[1]
	for i := 1; i < len(lines)-1; i++ {
		if endIndex > len(lines[i]) {
			endIndex = len(lines[i])
		}
		sizeString := lines[i][startIndex:endIndex]
		c.Assert(strings.TrimSpace(sizeString), checker.Matches, humanSizeRegexRaw, check.Commentf("The size '%s' was not in human format", sizeString))
	}
}
