package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/docker/pkg/stringid"
	"github.com/go-check/check"
)

func (s *DockerSuite) TestRmiWithContainerFails(c *check.C) {
	errSubstr := "is using it"

	// create a container
	out, _ := dockerCmd(c, "run", "-d", "busybox", "true")

	cleanedContainerID := strings.TrimSpace(out)

	// try to delete the image
	out, _, err := dockerCmdWithError("rmi", "busybox")
	// Container is using image, should not be able to rmi
	c.Assert(err, checker.NotNil)
	// Container is using image, error message should contain errSubstr
	c.Assert(out, checker.Contains, errSubstr, check.Commentf("Container: %q", cleanedContainerID))

	// make sure it didn't delete the busybox name
	images, _ := dockerCmd(c, "images")
	// The name 'busybox' should not have been removed from images
	c.Assert(images, checker.Contains, "busybox")
}

func (s *DockerSuite) TestRmiTag(c *check.C) {
	imagesBefore, _ := dockerCmd(c, "images", "-a")
	dockerCmd(c, "tag", "busybox", "utest:tag1")
	dockerCmd(c, "tag", "busybox", "utest/docker:tag2")
	dockerCmd(c, "tag", "busybox", "utest:5000/docker:tag3")
	{
		imagesAfter, _ := dockerCmd(c, "images", "-a")
		c.Assert(strings.Count(imagesAfter, "\n"), checker.Equals, strings.Count(imagesBefore, "\n")+3, check.Commentf("before: %q\n\nafter: %q\n", imagesBefore, imagesAfter))
	}
	dockerCmd(c, "rmi", "utest/docker:tag2")
	{
		imagesAfter, _ := dockerCmd(c, "images", "-a")
		c.Assert(strings.Count(imagesAfter, "\n"), checker.Equals, strings.Count(imagesBefore, "\n")+2, check.Commentf("before: %q\n\nafter: %q\n", imagesBefore, imagesAfter))
	}
	dockerCmd(c, "rmi", "utest:5000/docker:tag3")
	{
		imagesAfter, _ := dockerCmd(c, "images", "-a")
		c.Assert(strings.Count(imagesAfter, "\n"), checker.Equals, strings.Count(imagesBefore, "\n")+1, check.Commentf("before: %q\n\nafter: %q\n", imagesBefore, imagesAfter))

	}
	dockerCmd(c, "rmi", "utest:tag1")
	{
		imagesAfter, _ := dockerCmd(c, "images", "-a")
		c.Assert(strings.Count(imagesAfter, "\n"), checker.Equals, strings.Count(imagesBefore, "\n"), check.Commentf("before: %q\n\nafter: %q\n", imagesBefore, imagesAfter))

	}
}

func (s *DockerSuite) TestRmiImgIDMultipleTag(c *check.C) {
	out, _ := dockerCmd(c, "run", "-d", "busybox", "/bin/sh", "-c", "mkdir '/busybox-one'")

	containerID := strings.TrimSpace(out)

	// Wait for it to exit as cannot commit a running container on Windows, and
	// it will take a few seconds to exit
	if daemonPlatform == "windows" {
		err := waitExited(containerID, 60*time.Second)
		c.Assert(err, check.IsNil)
	}

	dockerCmd(c, "commit", containerID, "busybox-one")

	imagesBefore, _ := dockerCmd(c, "images", "-a")
	dockerCmd(c, "tag", "busybox-one", "busybox-one:tag1")
	dockerCmd(c, "tag", "busybox-one", "busybox-one:tag2")

	imagesAfter, _ := dockerCmd(c, "images", "-a")
	// tag busybox to create 2 more images with same imageID
	c.Assert(strings.Count(imagesAfter, "\n"), checker.Equals, strings.Count(imagesBefore, "\n")+2, check.Commentf("docker images shows: %q\n", imagesAfter))

	imgID := inspectField(c, "busybox-one:tag1", "Id")

	// run a container with the image
	out, _ = runSleepingContainerInImage(c, "busybox-one")

	containerID = strings.TrimSpace(out)

	// first checkout without force it fails
	out, _, err := dockerCmdWithError("rmi", imgID)
	expected := fmt.Sprintf("conflict: unable to delete %s (cannot be forced) - image is being used by running container %s", stringid.TruncateID(imgID), stringid.TruncateID(containerID))
	// rmi tagged in multiple repos should have failed without force
	c.Assert(err, checker.NotNil)
	c.Assert(out, checker.Contains, expected)

	dockerCmd(c, "stop", containerID)
	dockerCmd(c, "rmi", "-f", imgID)

	imagesAfter, _ = dockerCmd(c, "images", "-a")
	// rmi -f failed, image still exists
	c.Assert(imagesAfter, checker.Not(checker.Contains), imgID[:12], check.Commentf("ImageID:%q; ImagesAfter: %q", imgID, imagesAfter))
}

func (s *DockerSuite) TestRmiImgIDForce(c *check.C) {
	out, _ := dockerCmd(c, "run", "-d", "busybox", "/bin/sh", "-c", "mkdir '/busybox-test'")

	containerID := strings.TrimSpace(out)

	// Wait for it to exit as cannot commit a running container on Windows, and
	// it will take a few seconds to exit
	if daemonPlatform == "windows" {
		err := waitExited(containerID, 60*time.Second)
		c.Assert(err, check.IsNil)
	}

	dockerCmd(c, "commit", containerID, "busybox-test")

	imagesBefore, _ := dockerCmd(c, "images", "-a")
	dockerCmd(c, "tag", "busybox-test", "utest:tag1")
	dockerCmd(c, "tag", "busybox-test", "utest:tag2")
	dockerCmd(c, "tag", "busybox-test", "utest/docker:tag3")
	dockerCmd(c, "tag", "busybox-test", "utest:5000/docker:tag4")
	{
		imagesAfter, _ := dockerCmd(c, "images", "-a")
		c.Assert(strings.Count(imagesAfter, "\n"), checker.Equals, strings.Count(imagesBefore, "\n")+4, check.Commentf("before: %q\n\nafter: %q\n", imagesBefore, imagesAfter))
	}
	imgID := inspectField(c, "busybox-test", "Id")

	// first checkout without force it fails
	out, _, err := dockerCmdWithError("rmi", imgID)
	// rmi tagged in multiple repos should have failed without force
	c.Assert(err, checker.NotNil)
	// rmi tagged in multiple repos should have failed without force
	c.Assert(out, checker.Contains, "(must be forced) - image is referenced in one or more repositories", check.Commentf("out: %s; err: %v;", out, err))

	dockerCmd(c, "rmi", "-f", imgID)
	{
		imagesAfter, _ := dockerCmd(c, "images", "-a")
		// rmi failed, image still exists
		c.Assert(imagesAfter, checker.Not(checker.Contains), imgID[:12])
	}
}

func (s *DockerSuite) TestRmiTagWithExistingContainers(c *check.C) {
	container := "test-delete-tag"
	newtag := "busybox:newtag"
	bb := "busybox:latest"
	dockerCmd(c, "tag", bb, newtag)

	dockerCmd(c, "run", "--name", container, bb, "/bin/true")

	out, _ := dockerCmd(c, "rmi", newtag)
	c.Assert(strings.Count(out, "Untagged: "), checker.Equals, 1)
}

func (s *DockerSuite) TestRmiWithMultipleRepositories(c *check.C) {
	newRepo := "127.0.0.1:5000/busybox"
	oldRepo := "busybox"
	newTag := "busybox:test"
	dockerCmd(c, "tag", oldRepo, newRepo)

	dockerCmd(c, "run", "--name", "test", oldRepo, "touch", "/abcd")

	dockerCmd(c, "commit", "test", newTag)

	out, _ := dockerCmd(c, "rmi", newTag)
	c.Assert(out, checker.Contains, "Untagged: "+newTag)
}

func (s *DockerSuite) TestRmiBlank(c *check.C) {
	out, _, err := dockerCmdWithError("rmi", " ")
	// Should have failed to delete ' ' image
	c.Assert(err, checker.NotNil)
	// Wrong error message generated
	c.Assert(out, checker.Not(checker.Contains), "no such id", check.Commentf("out: %s", out))
	// Expected error message not generated
	c.Assert(out, checker.Contains, "image name cannot be blank", check.Commentf("out: %s", out))
}

func (*DockerSuite) TestRmiParentImageFail(c *check.C) {
	parent := inspectField(c, "busybox", "Parent")
	out, _, err := dockerCmdWithError("rmi", parent)
	c.Assert(err, check.NotNil)
	if !strings.Contains(out, "image has dependent child images") {
		c.Fatalf("rmi should have failed because it's a parent image, got %s", out)
	}
}

func (s *DockerSuite) TestRmiWithParentInUse(c *check.C) {
	out, _ := dockerCmd(c, "create", "busybox")
	cID := strings.TrimSpace(out)

	out, _ = dockerCmd(c, "commit", cID)
	imageID := strings.TrimSpace(out)

	out, _ = dockerCmd(c, "create", imageID)
	cID = strings.TrimSpace(out)

	out, _ = dockerCmd(c, "commit", cID)
	imageID = strings.TrimSpace(out)

	dockerCmd(c, "rmi", imageID)
}

// #18873
func (s *DockerSuite) TestRmiByIDHardConflict(c *check.C) {
	dockerCmd(c, "create", "busybox")

	imgID := inspectField(c, "busybox:latest", "Id")

	_, _, err := dockerCmdWithError("rmi", imgID[:12])
	c.Assert(err, checker.NotNil)

	// check that tag was not removed
	imgID2 := inspectField(c, "busybox:latest", "Id")
	c.Assert(imgID, checker.Equals, imgID2)
}
