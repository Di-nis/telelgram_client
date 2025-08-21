package telegram

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/message"
	"github.com/gotd/td/telegram/updates"
	updhook "github.com/gotd/td/telegram/updates/hook"
	"github.com/gotd/td/tg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lj "gopkg.in/natefinch/lumberjack.v2"
)

func sessionFolder(phone string) string {
	var out []rune
	for _, r := range phone {
		if r >= '0' && r <= '9' {
			out = append(out, r)
		}
	}
	return "phone-" + string(out)
}

type Params struct {
	Phone   string
	AppID   int
	AppHash string
	Session string
}

func NewParams(phone, appHash, sessionAllDir string, appID int) *Params {
	sessionClientDir := sessionFolder(phone)
	session := filepath.Join(sessionAllDir, sessionClientDir)

	return &Params{
		Phone:   phone,
		AppID:   appID,
		AppHash: appHash,
		Session: session,
	}
}

type Client struct {
	Client     *telegram.Client
	Params     *Params
	Dispatcher tg.UpdateDispatcher
	Flow       auth.Flow
	Gaps       *updates.Manager
}

func NewClient() *Client {
	params := NewParams()
	return &Client{
		Params: params,
	}
}

func (t *Client) NoNameFunction() error {
	logFilePath := filepath.Join(t.Params.Session, "log.jsonl")
	fmt.Printf("Storing session in %s, logs in %s\n", t.Params.Session, logFilePath)

	// Setting up logging to file with rotation.
	//
	// Log to file, so we don't interfere with prompts and messages to user.
	logWriter := zapcore.AddSync(&lj.Logger{
		Filename:   logFilePath,
		MaxBackups: 3,
		MaxSize:    1, // megabytes
		MaxAge:     7, // days
	})
	logCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		logWriter,
		zap.DebugLevel,
	)
	lg := zap.New(logCore)
	defer func() { _ = lg.Sync() }()

	// So, we are storing session information in a current directory, under subdirectory "session/phone_hash"
	sessionStorage := &telegram.FileSessionStorage{
		Path: filepath.Join(t.Params.Session, "session.json"),
	}

	t.Dispatcher = tg.NewUpdateDispatcher()

	t.Gaps = updates.New(updates.Config{
		Handler: t.Dispatcher,
	})

	// Filling client options.
	options := telegram.Options{
		Logger:         lg,             // Passing logger for observability.
		SessionStorage: sessionStorage, // Setting up session sessionStorage to store auth data.
		UpdateHandler:  t.Gaps,
		Middlewares: []telegram.Middleware{
			updhook.UpdateHook(t.Gaps.Handle),
		},
	}
	t.Client = telegram.NewClient(t.Params.AppID, t.Params.AppHash, options)

	t.Flow = auth.NewFlow(
		auth.Constant(t.Params.Phone, "", auth.CodeAuthenticatorFunc(func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
			return "", fmt.Errorf("no session found. Please run: go run setup_telegram.go")
		})),
		auth.SendCodeOptions{},
	)

	return nil
}

func (t *Client) SendMessageToGroup(msg string) error {
	n8nGroupID, _ := strconv.ParseInt(os.Getenv("N8N_GROUP_ID"), 10, 64)

	// Контекст для работы с API
	ctx := context.Background()

	// Аутентификация
	if err := t.Client.Run(ctx, func(ctx context.Context) error {
		// Процесс авторизации
		if err := t.Client.Auth().IfNecessary(ctx, t.Flow); err != nil {
			return err
		}

		// Создаём InputPeer для группы
		inputPeer := &tg.InputPeerChat{
			ChatID: n8nGroupID,
		}

		// Отправляем сообщение
		sender := message.NewSender(t.Client.API())

		if _, err := sender.To(inputPeer).Text(ctx, msg); err != nil {
			return fmt.Errorf("send message failed: %w", err)
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (t *Client) SendMessageToBot(username, msg string) error {

	// Контекст для работы с API
	ctx := context.Background()

	// Аутентификация
	if err := t.Client.Run(ctx, func(ctx context.Context) error {
		// Процесс авторизации

		if err := t.Client.Auth().IfNecessary(ctx, t.Flow); err != nil {
			return err
		}

		// Вызов метода contacts.ResolveUsername
		res, err := t.Client.API().ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{
			Username: username,
		})
		if err != nil {
			return fmt.Errorf("failed to resolve username: %w", err)
		}

		// Проверяем, что пользователь найден
		if len(res.Users) == 0 {
			return fmt.Errorf("user %q not found", username)
		}

		// Берём первого пользователя из результата (обычно один)
		user, ok := res.Users[0].(*tg.User)
		if !ok {
			return fmt.Errorf("unexpected user type %T", res.Users[0])
		}

		// Создаём InputPeer для пользователя
		inputPeer := &tg.InputPeerUser{
			UserID:     user.ID,
			AccessHash: user.AccessHash,
		}

		// Отправляем сообщение
		sender := message.NewSender(t.Client.API())

		if _, err := sender.To(inputPeer).Text(ctx, msg); err != nil {
			return fmt.Errorf("send message failed: %w", err)
		}

		fmt.Printf("Message sent successfully: %s\n", msg)
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (t *Client) Setup() {
	phone := t.Params.Phone
	appID := t.Params.AppID
	appHash := t.Params.AppHash

	fmt.Println("Telegram Session Setup")
	fmt.Println("======================")

	sessionDir := filepath.Join("session", sessionFolder(phone))
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		panic(err)
	}
	logFilePath := filepath.Join(sessionDir, "log.jsonl")

	fmt.Printf("Using phone: %s\n", phone)
	fmt.Printf("Storing session in %s\n", sessionDir)

	logWriter := zapcore.AddSync(&lj.Logger{
		Filename:   logFilePath,
		MaxBackups: 3,
		MaxSize:    1,
		MaxAge:     7,
	})
	logCore := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		logWriter,
		zap.DebugLevel,
	)
	lg := zap.New(logCore)
	defer func() { _ = lg.Sync() }()

	sessionStorage := &telegram.FileSessionStorage{
		Path: filepath.Join(sessionDir, "session.json"),
	}

	options := telegram.Options{
		Logger:         lg,
		SessionStorage: sessionStorage,
	}
	client := telegram.NewClient(appID, appHash, options)

	ctx := context.Background()

	if err := client.Run(ctx, func(ctx context.Context) error {
		reader := bufio.NewReader(os.Stdin)

		flow := auth.NewFlow(
			auth.Constant(phone, "", auth.CodeAuthenticatorFunc(func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
				fmt.Printf("\n=== TELEGRAM VERIFICATION ===\n")
				fmt.Printf("Code sent to: %s\n", phone)
				fmt.Printf("Code type: %d\n", sentCode.Type.TypeID())
				fmt.Printf("==============================\n")
				fmt.Print("Enter the 5-digit verification code: ")

				for {
					code, err := reader.ReadString('\n')
					if err != nil {
						fmt.Printf("Error reading input: %v\n", err)
						return "", err
					}
					code = strings.TrimSpace(code)
					if len(code) >= 4 && len(code) <= 6 {
						fmt.Printf("Submitting code: %s\n", code)
						return code, nil
					}
					fmt.Printf("Invalid code length (%d). Enter 4-6 digit code: ", len(code))
				}
			})),
			auth.SendCodeOptions{},
		)

		if err := client.Auth().IfNecessary(ctx, flow); err != nil {
			return err
		}

		fmt.Println("Telegram session created successfully!")
		fmt.Println("Now you can run your tests!")
		return nil
	}); err != nil {
		fmt.Printf("\nError during authentication: %v\n", err)
		fmt.Println("\nCommon issues:")
		fmt.Println("- Code expired (request a new one)")
		fmt.Println("- Wrong code format (try without spaces/dashes)")
		fmt.Println("- Network connection issues")
		fmt.Println("\nTry running the command again.")
		os.Exit(1)
	}
}
