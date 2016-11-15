package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/docker/pkg/stringid"
	"github.com/go-check/check"
)

func (s *DockerSuite) TestImagesEnsureImageIsListed(c *check.C) {
	testRequires(c, DaemonIsLinux)
	imagesOut, _ := dockerCmd(c, "images")
	c.Assert(imagesOut, checker.Contains, "busybox")
}

func (s *DockerSuite) TestImagesEnsureImageWithTagIsListed(c *check.C) {
	testRequires(c, DaemonIsLinux)

	name := "imagewithtag"
	dockerCmd(c, "tag", "busybox", name+":v1")
	dockerCmd(c, "tag", "busybox", name+":v1v1")
	dockerCmd(c, "tag", "busybox", name+":v2")

	imagesOut, _ := dockerCmd(c, "images", name+":v1")
	c.Assert(imagesOut, checker.Contains, name)
	c.Assert(imagesOut, checker.Contains, "v1")
	c.Assert(imagesOut, checker.Not(checker.Contains), "v2")
	c.Assert(imagesOut, checker.Not(checker.Contains), "v1v1")

	imagesOut, _ = dockerCmd(c, "images", name)
	c.Assert(imagesOut, checker.Contains, name)
	c.Assert(imagesOut, checker.Contains, "v1")
	c.Assert(imagesOut, checker.Contains, "v1v1")
	c.Assert(imagesOut, checker.Contains, "v2")
}

func (s *DockerSuite) TestImagesEnsureImageWithBadTagIsNotListed(c *check.C) {
	imagesOut, _ := dockerCmd(c, "images", "busybox:nonexistent")
	c.Assert(imagesOut, checker.Not(checker.Contains), "busybox")
}

func (s *DockerSuite) TestImagesErrorWithInvalidFilterNameTest(c *check.C) {
	out, _, err := dockerCmdWithError("images", "-f", "FOO=123")
	c.Assert(err, checker.NotNil)
	c.Assert(out, checker.Contains, "Invalid filter")
}

func assertImageList(out string, expected []string) bool {
	lines := strings.Split(strings.Trim(out, "\n "), "\n")

	if len(lines)-1 != len(expected) {
		return false
	}

	imageIDIndex := strings.Index(lines[0], "IMAGE ID")
	for i := 0; i < len(expected); i++ {
		imageID := lines[i+1][imageIDIndex : imageIDIndex+12]
		found := false
		for _, e := range expected {
			if imageID == e[7:19] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (s *DockerSuite) TestImagesEnsureDanglingImageOnlyListedOnce(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// create container 1
	out, _ := dockerCmd(c, "run", "-d", "busybox", "true")
	containerID1 := strings.TrimSpace(out)

	// tag as foobox
	out, _ = dockerCmd(c, "commit", containerID1, "foobox")
	imageID := stringid.TruncateID(strings.TrimSpace(out))

	// overwrite the tag, making the previous image dangling
	dockerCmd(c, "tag", "busybox", "foobox")

	out, _ = dockerCmd(c, "images", "-q", "-f", "dangling=true")
	// Expect one dangling image
	c.Assert(strings.Count(out, imageID), checker.Equals, 1)

	out, _ = dockerCmd(c, "images", "-q", "-f", "dangling=false")
	//dangling=false would not include dangling images
	c.Assert(out, checker.Not(checker.Contains), imageID)

	out, _ = dockerCmd(c, "images")
	//docker images still include dangling images
	c.Assert(out, checker.Contains, imageID)

}

func (s *DockerSuite) TestImagesWithIncorrectFilter(c *check.C) {
	out, _, err := dockerCmdWithError("images", "-f", "dangling=invalid")
	c.Assert(err, check.NotNil)
	c.Assert(out, checker.Contains, "Invalid filter")
}

// #18181
func (s *DockerSuite) TestImagesFilterNameWithPort(c *check.C) {
	tag := "a.b.c.d:5000/hello"
	dockerCmd(c, "tag", "busybox", tag)
	out, _ := dockerCmd(c, "images", tag)
	c.Assert(out, checker.Contains, tag)

	out, _ = dockerCmd(c, "images", tag+":latest")
	c.Assert(out, checker.Contains, tag)

	out, _ = dockerCmd(c, "images", tag+":no-such-tag")
	c.Assert(out, checker.Not(checker.Contains), tag)
}

func (s *DockerSuite) TestImagesFormat(c *check.C) {
	// testRequires(c, DaemonIsLinux)
	tag := "myimage"
	dockerCmd(c, "tag", "busybox", tag+":v1")
	dockerCmd(c, "tag", "busybox", tag+":v2")

	out, _ := dockerCmd(c, "images", "--format", "{{.Repository}}", tag)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	expected := []string{"myimage", "myimage"}
	var names []string
	for _, l := range lines {
		names = append(names, l)
	}
	c.Assert(expected, checker.DeepEquals, names, check.Commentf("Expected array with truncated names: %v, got: %v", expected, names))
}

// ImagesDefaultFormatAndQuiet
func (s *DockerSuite) TestImagesFormatDefaultFormat(c *check.C) {
	testRequires(c, DaemonIsLinux)

	// create container 1
	out, _ := dockerCmd(c, "run", "-d", "busybox", "true")
	containerID1 := strings.TrimSpace(out)

	// tag as foobox
	out, _ = dockerCmd(c, "commit", containerID1, "myimage")
	imageID := stringid.TruncateID(strings.TrimSpace(out))

	config := `{
		"imagesFormat": "{{ .ID }} default"
}`
	d, err := ioutil.TempDir("", "integration-cli-")
	c.Assert(err, checker.IsNil)
	defer os.RemoveAll(d)

	err = ioutil.WriteFile(filepath.Join(d, "config.json"), []byte(config), 0644)
	c.Assert(err, checker.IsNil)

	out, _ = dockerCmd(c, "--config", d, "images", "-q", "myimage")
	c.Assert(out, checker.Equals, imageID+"\n", check.Commentf("Expected to print only the image id, got %v\n", out))
}
