/*
 * Copyright 2016 Igor Moochnick
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package docker_compose

import (
	"config2vault/log"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/docker/libcompose/docker"
	lclient "github.com/docker/libcompose/docker/client"
	"github.com/docker/libcompose/docker/container"
	"github.com/docker/libcompose/docker/ctx"
	"github.com/docker/libcompose/project"
	"github.com/docker/libcompose/project/options"
	"golang.org/x/net/context"
)

type ContainerInfo struct {
	ID     string
	State  string
	Status string
}

type DockerComposeProject struct {
	project project.APIProject
	context ctx.Context
	Name    string
}

type DockerContainer struct {
	project   *DockerComposeProject
	container interface{}
}

func newDockerComposeProject(project project.APIProject, context ctx.Context) DockerComposeProject {
	return DockerComposeProject{
		project: project,
		context: context,
	}
}

func (pr *DockerComposeProject) ProjectName() string {
	return pr.context.ProjectName
}

func GetDockerHostIP() string {
	// DOCKER_CERT_PATH
	// DOCKER_HOST
	// DOCKER_MACHINE_NAME
	// DOCKER_TLS_VERIFY
	env_docker_host := os.Getenv("DOCKER_HOST")
	if env_docker_host == "" {
		return ""
	}
	docker_host, err := url.Parse(env_docker_host)
	if err != nil {
		return ""
	}
	parts := strings.Split(docker_host.Host, ":")
	return parts[0]
}

func NewDockerComposeProjectFromString(composeProject string, t *testing.T) (*DockerComposeProject, error) {
	context := ctx.Context{
		Context: project.Context{
			ComposeBytes: [][]byte{[]byte(composeProject)},
			ProjectName:  "test-project",
		},
	}
	pr, err := docker.NewProject(&context, nil)

	if err != nil {
		log.Fatal(err)
	}

	dpr := newDockerComposeProject(pr, context)
	return &dpr, err
}

func NewDockerComposeProjectFromFile(projectName string, composeFilePath string) (*DockerComposeProject, error) {
	context := ctx.Context{
		Context: project.Context{
			ComposeFiles: []string{composeFilePath},
			ProjectName:  projectName,
		},
	}
	pr, err := docker.NewProject(&context, nil)

	if err != nil {
		log.Error(err)
		return nil, err
	}

	dpr := newDockerComposeProject(pr, context)
	return &dpr, err
}

func (pr *DockerComposeProject) Up() (string, func(), error) {
	err := pr.project.Up(context.Background(), options.Up{})

	if err != nil {
		log.Fatal(err)
	}

	removeVolume := true
	removeOrphans := true
	removeImages := options.ImageType("local")

	// Leave images behind for debug purposes
	if log.GetLevel() == log.DebugLevel {
		removeVolume = false
		removeOrphans = false
		removeImages = "none"
	}

	dfrFunc := func() {
		pr.project.Down(context.Background(), options.Down{
			RemoveVolume:  removeVolume,
			RemoveOrphans: removeOrphans,
			RemoveImages:  removeImages,
		})
	}

	return GetDockerHostIP(), dfrFunc, err
}

func IsRunning(projectName string, containerName string) (bool, error) {
	name := fmt.Sprintf("%s_%s_1", projectName, containerName)

	client, _ := lclient.Create(lclient.Options{})
	container, err := container.Get(context.Background(), client, name)
	if err != nil {
		return false, err
	}
	if container == nil {
		return false, nil
	}

	return container.State.Running, nil
}
