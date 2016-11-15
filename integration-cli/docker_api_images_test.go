package main

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/docker/engine-api/types"
	"github.com/go-check/check"
)

func (s *DockerSuite) TestApiImagesFilter(c *check.C) {
	name := "utest:tag1"
	name2 := "utest/docker:tag2"
	name3 := "utest:5000/docker:tag3"
	for _, n := range []string{name, name2, name3} {
		dockerCmd(c, "tag", "busybox", n)
	}
	type image types.Image
	getImages := func(filter string) []image {
		v := url.Values{}
		v.Set("filter", filter)
		status, b, err := sockRequest("GET", "/images/json?"+v.Encode(), nil)
		c.Assert(err, checker.IsNil)
		c.Assert(status, checker.Equals, http.StatusOK)

		var images []image
		err = json.Unmarshal(b, &images)
		c.Assert(err, checker.IsNil)

		return images
	}

	//incorrect number of matches returned
	images := getImages("utest*/*")
	c.Assert(images[0].RepoTags, checker.HasLen, 2)

	images = getImages("utest")
	c.Assert(images[0].RepoTags, checker.HasLen, 1)

	images = getImages("utest*")
	c.Assert(images[0].RepoTags, checker.HasLen, 1)

	images = getImages("*5000*/*")
	c.Assert(images[0].RepoTags, checker.HasLen, 1)
}

// #14846
func (s *DockerSuite) TestApiImagesSearchJSONContentType(c *check.C) {
	testRequires(c, Network)

	res, b, err := sockRequestRaw("GET", "/images/search?term=test", nil, "application/json")
	c.Assert(err, check.IsNil)
	b.Close()
	c.Assert(res.StatusCode, checker.Equals, http.StatusOK)
	c.Assert(res.Header.Get("Content-Type"), checker.Equals, "application/json")
}
