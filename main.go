package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"github.com/gin-gonic/gin"
	"encoding/hex"
)

type User struct {
	Host       string
	User       string
	PrivateKey []byte
	UserID     string
}

type SSHConnection struct {
	Client  *ssh.Client
	Session *ssh.Session
}

var users map[string]*User
var sshConnections map[string]*SSHConnection
var mu, muSSH sync.Mutex


func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}


func findUserByUserID(userID string) (*User, bool) {
    for _, user := range users {
        if user.UserID == userID {
            return user, true
        }
    }

    return nil, false
}
func main() {
	users = make(map[string]*User)
	sshConnections = make(map[string]*SSHConnection)

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
		c.Header("Access-Control-Allow-Credentials", "true")
	
		if c.Request.Method == "OPTIONS" {
			// Preflight request. Reply successfully:
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
			c.JSON(http.StatusOK, gin.H{"message": "Preflight request successful"})
			return
		}
	
		c.Next()
	})
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.POST("/connect", func(c *gin.Context) {
		host := c.PostForm("host")
		user := c.PostForm("user")
		userid := c.PostForm("id")
		// userID := c.PostForm("userID")
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

		// Generate a random string of 8 characters
		randomString := generateRandomString(8)

		mu.Lock()
		users[user] = &User{
			Host:       host,
			User:       user,
			PrivateKey: privateKeyBytes,
			UserID:      userid,
		}
		mu.Unlock()

		c.String(http.StatusOK, "SSH details saved for user %s with ID %s", user, randomString)
	})



	r.GET("/connect/:user", func(c *gin.Context) {
		user := c.Param("user")
		
		u, ok := findUserByUserID(user)

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
		_, ok := findUserByUserID(user)

		// _, ok := users[user]
	
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
			// Close the session after the command is executed
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
			c.String(http.StatusInternalServerError, "Error starting command: %s", err)
			return
		}
	
		err = conn.Session.Wait()
		if err != nil {
			c.String(http.StatusInternalServerError, "Error waiting for command to finish: %s", err)
			return
		}
	
		c.String(http.StatusOK, "Command executed successfully")
	})
	

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}