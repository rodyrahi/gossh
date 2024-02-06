package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

type User struct {
	Host       string
	User       string
	Password   string
	PrivateKey []byte
	UserID     string
	GID        string // Add group ID
}

type SSHConnection struct {
	Client  *ssh.Client
	Session *ssh.Session
}

var users map[string]*User
var sshConnections map[string]*SSHConnection
var mu, muSSH, muFile sync.Mutex

const usersFileName = "users.json"

func findUserByUserID(userID string) (*User, bool) {
	for _, user := range users {
		if user.UserID == userID {
			return user, true
		}
	}
	return nil, false
}

func findUserByGID(gid string) (*User, bool) {
	for _, user := range users {
		if user.GID == gid {
			return user, true
		}
	}
	return nil, false
}

// Function to read users from the file
func readUsersFromFile() error {
	muFile.Lock()
	defer muFile.Unlock()

	content, err := ioutil.ReadFile(usersFileName)
	if err != nil {
		return err
	}

	return json.Unmarshal(content, &users)
}

// Function to write users to the file
func writeUsersToFile() error {
	muFile.Lock()
	defer muFile.Unlock()

	// Create a simplified structure for writing
	var simplifiedUsers = make(map[string]*User)
	for gid, user := range users {
		simplifiedUsers[gid] = &User{
			UserID: user.UserID,
			GID:    user.GID,
		}
	}

	content, err := json.MarshalIndent(simplifiedUsers, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(usersFileName, content, 0644)
}

func main() {
	users = make(map[string]*User)
	sshConnections = make(map[string]*SSHConnection)

	// Load existing users from the file
	if err := readUsersFromFile(); err != nil {
		log.Fatalf("Error reading users from file: %s", err)
	}

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	r.Use(func(c *gin.Context) {

		// Get the server's IP address
		serverIP := "127.0.0.1" // Change this to the actual IP address of your server

		// Get the client's IP address
		clientIP := c.ClientIP()

		println(clientIP , serverIP)

		// Check if the client's IP matches the server's IP
		if clientIP != serverIP {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
			c.JSON(http.StatusOK, gin.H{"message": "Preflight request successful"})
			return
		}

		c.Next()
	})

	r.POST("/connect", func(c *gin.Context) {
		host := c.PostForm("host")
		user := c.PostForm("user")
		password := c.PostForm("password")
		userid := c.PostForm("id")
		gid := c.PostForm("gid")
		privateKey, _, err := c.Request.FormFile("privateKey")

		if err != nil {
			c.String(http.StatusBadRequest, "Error reading private key: %s", err)
			return
		}

		privateKeyBytes, err := ioutil.ReadAll(privateKey)

		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading private key: %s", err)
			return
		}

		mu.Lock()
		users[gid] = &User{
			UserID: userid,
			GID:    gid, // Assuming you have a function to generate unique GIDs
		}
		mu.Unlock()
		signer, err := ssh.ParsePrivateKey(privateKeyBytes)
		// Attempt to connect to the SSH server
		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
				ssh.PublicKeys(signer),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", host), config)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error connecting to SSH server: %s", err)
			return
		}

		// Save users to the file after a successful SSH connection
		mu.Lock()
		users[gid].GID = gid
		sshConnections[users[gid].GID] = &SSHConnection{
			Client: client,
		}
		mu.Unlock()

		// Save users to the file after adding a new user
		if err := writeUsersToFile(); err != nil {
			c.String(http.StatusInternalServerError, "Error writing users to file: %s", err)
			return
		}

		c.String(http.StatusOK, "SSH details saved for user %s with GID %s", user, users[gid].GID)
	})

	r.GET("/connect/:user", func(c *gin.Context) {
		user := c.Param("user")

		u, ok := findUserByGID(user)

		if !ok {
			c.String(http.StatusNotFound, "User not found")
			return
		}

		signer, err := ssh.ParsePrivateKey(u.PrivateKey)
		if err != nil {
			c.String(http.StatusInternalServerError, "Error parsing private key: %s", err)
			return
		}

		muSSH.Lock()
		_, ok = sshConnections[user]
		if !ok {
			config := &ssh.ClientConfig{
				User: u.User,
				Auth: []ssh.AuthMethod{
					ssh.Password(u.Password),
					ssh.PublicKeys(signer),
				},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}

			client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", u.Host), config)
			if err != nil {
				muSSH.Unlock()
				c.String(http.StatusInternalServerError, "Error connecting to SSH server: %s", err)
				return
			}

			sshConnections[user] = &SSHConnection{
				Client: client,
			}
		}
		muSSH.Unlock()

		c.String(http.StatusOK, "Connected to SSH server for user %s", user)
	})

	r.POST("/execute/:user", func(c *gin.Context) {
		user := c.Param("user")
		_, ok := findUserByGID(user)

		if !ok {
			c.String(http.StatusNotFound, "User not found")
			return
		}

		muSSH.Lock()
		conn, ok := sshConnections[user]
		muSSH.Unlock()

		if !ok {
			c.String(http.StatusInternalServerError, "SSH connection not found for user %s", user)
			return
		}

		if conn.Session == nil {
			session, err := conn.Client.NewSession()
			if err != nil {
				c.String(http.StatusInternalServerError, "Error creating SSH session: %s", err)
				return
			}
			conn.Session = session
		}

		defer func() {
			muSSH.Lock()
			defer muSSH.Unlock()
			if conn.Session != nil {
				conn.Session.Close()
				conn.Session = nil
			}
		}()

		command := c.PostForm("command")

		conn.Session.Stdout = c.Writer
		conn.Session.Stderr = c.Writer
		conn.Session.Stdin = c.Request.Body

		err := conn.Session.Start(command)
		if err != nil {
			c.String(http.StatusOK, "error:", err)
			return
		}

		err = conn.Session.Wait()
		if err != nil {
			c.String(http.StatusInternalServerError, "Error waiting for command to finish: %s", err)
			return
		}

		c.String(http.StatusOK, "")
	})

	r.GET("/user/:user", func(c *gin.Context) {
		user := c.Param("user")
		_, ok := findUserByGID(user)

		if ok {
			c.JSON(http.StatusOK, gin.H{"exists": true})
		} else {
			c.JSON(http.StatusNotFound, gin.H{"exists": false})
		}
	})

	if err := r.Run(":8181"); err != nil {
		log.Fatal(err)
	}
}
