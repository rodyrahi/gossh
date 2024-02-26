package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"io"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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

var (
	users           map[string]*User
	sshConnections  map[string]*SSHConnection
	mu, muSSH, muFile sync.Mutex
	upgrader        = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

const usersFileName = "users.json"

func findUserByGID(gid string) (*User, bool) {
	for _, user := range users {
		if user.GID == gid {
			return user, true
		}
	}
	return nil, false
}

func readUsersFromFile() error {
	muFile.Lock()
	defer muFile.Unlock()

	content, err := ioutil.ReadFile(usersFileName)
	if err != nil {
		return err
	}

	return json.Unmarshal(content, &users)
}

func writeUsersToFile() error {
	muFile.Lock()
	defer muFile.Unlock()

	type simpleUser struct {
		User   string
		UserID string
		GID    string
	}

	var simplifiedUsers = make(map[string]*simpleUser)

	for gid, user := range users {
		copiedUser := &simpleUser{
			User:   user.User,
			UserID: user.UserID,
			GID:    user.GID,
		}

		simplifiedUsers[gid] = copiedUser
	}

	content, err := json.MarshalIndent(simplifiedUsers, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(usersFileName, content, 0644)
	if err != nil {
		return err
	}

	return nil
}




// handleTerminal handles the WebSocket-based terminal.
func handleTerminal(c *gin.Context) {
    userID := c.Param("user")
    _, ok := findUserByGID(userID)
    if !ok {
        c.String(http.StatusNotFound, "User not found")
        return
    }

    muSSH.Lock()
    conn, ok := sshConnections[userID]
    muSSH.Unlock()

    if !ok {
        c.String(http.StatusInternalServerError, "SSH connection not found for user %s", userID)
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

    ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        log.Println(err)
        return
    }
    defer ws.Close()

    // Attach WebSocket to SSH session (stdin)
    stdin, err := conn.Session.StdinPipe()
    if err != nil {
        log.Println(err)
        return
    }

    // Attach SSH session to WebSocket (stdout)
    stdout, err := conn.Session.StdoutPipe()
    if err != nil {
        log.Println(err)
        return
    }

    closeChannel := make(chan struct{}) // Channel to signal closure

    // Bidirectional copy between WebSocket and SSH session
    go func() {
        defer close(closeChannel) // Signal closure when the function exits
        defer ws.Close()
        defer stdin.Close()
        defer conn.Session.Close() // Close SSH session when WebSocket is closed

        // Copy from WebSocket to SSH session (stdin)
        for {
            messageType, p, err := ws.ReadMessage()
            if err != nil {
                if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
                    // WebSocket connection closed, break out of the loop
                    return
                }
                log.Println("WebSocket read error:", err)
                return
            }
            if messageType != websocket.TextMessage && messageType != websocket.BinaryMessage {
                log.Println("Unsupported WebSocket message type")
                return
            }
            if _, err := stdin.Write(p); err != nil {
                log.Println("WebSocket to SSH copy error:", err)
                return
            }
        }
    }()

    // Copy from SSH session (stdout) to WebSocket
    go func() {
        defer close(closeChannel) // Signal closure when the function exits

        for {
            buf := make([]byte, 4096)
            n, err := stdout.Read(buf)
            if err != nil {
                if err == io.EOF {
                    // SSH session closed, break out of the loop
                    return
                }
                log.Println("SSH to WebSocket copy error:", err)
                return
            }
            if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
                log.Println("SSH to WebSocket write error:", err)
                return
            }
        }
    }()

    // Wait for closure from either side
    <-closeChannel
}



func main() {
	users = make(map[string]*User)
	sshConnections = make(map[string]*SSHConnection)

	if err := readUsersFromFile(); err != nil {
		log.Fatalf("Error reading users from file: %s", err)
	}

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	r.Use(func(c *gin.Context) {
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
		userID := c.PostForm("id")
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
			User:   user,
			UserID: userID,
			GID:    gid,
		}
		mu.Unlock()
		signer, err := ssh.ParsePrivateKey(privateKeyBytes)

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

		mu.Lock()
		users[gid].GID = gid
		sshConnections[users[gid].GID] = &SSHConnection{
			Client: client,
		}
		mu.Unlock()

		if err := writeUsersToFile(); err != nil {
			c.String(http.StatusInternalServerError, "Error writing users to file: %s", err)
			return
		}

		c.String(http.StatusOK, "SSH details saved for user %s with GID %s", user, users[gid].GID)
	})

	r.GET("/connect/:user", func(c *gin.Context) {
		userID := c.Param("user")

		u, ok := findUserByGID(userID)

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
		_, ok = sshConnections[userID]
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

			sshConnections[userID] = &SSHConnection{
				Client: client,
			}
		}
		muSSH.Unlock()

		c.String(http.StatusOK, "Connected to SSH server for user %s", userID)
	})

	r.POST("/execute/:user", func(c *gin.Context) {
		userID := c.Param("user")
		_, ok := findUserByGID(userID)

		if !ok {
			c.String(http.StatusNotFound, "User not found")
			return
		}

		muSSH.Lock()
		conn, ok := sshConnections[userID]
		muSSH.Unlock()

		if !ok {
			c.String(http.StatusInternalServerError, "SSH connection not found for user %s", userID)
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
		userID := c.Param("user")

		muSSH.Lock()
		defer muSSH.Unlock()

		conn, ok := sshConnections[userID]
		if ok && conn.Client != nil {
			c.JSON(http.StatusOK, gin.H{"exists": true})
		} else {
			c.JSON(http.StatusNotFound, gin.H{"exists": false})
		}
	})

	r.GET("/username/:user", func(c *gin.Context) {
		userID := c.Param("user")

		plan, err := ioutil.ReadFile(usersFileName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading file"})
			return
		}

		var data map[string]interface{}
		if err := json.Unmarshal(plan, &data); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error unmarshalling JSON"})
			return
		}

		userData, ok := data[userID]
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": userData})
	})





	r.GET("/terminal/:user", handleTerminal)

	// Graceful shutdown
	server := &http.Server{
		Addr:    ":8181",
		Handler: r,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe error: %s", err)
		}
	}()

	// Graceful shutdown handling
	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("Server is shutting down...")

	// Close the WebSocket connections and the SSH sessions
	muSSH.Lock()
	for _, conn := range sshConnections {
		if conn.Session != nil {
			conn.Session.Close()
		}
	}
	muSSH.Unlock()

	// Shutdown the HTTP server
	if err := server.Shutdown(context.Background()); err != nil {
		log.Fatalf("Server shutdown error: %s", err)
	}

	log.Println("Server has stopped.")
}
