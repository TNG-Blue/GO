package main

import (
	"bytes"
	_ "bytes"
	"encoding/json"
	_ "encoding/json"
	"fmt"
	"github.com/tealeg/xlsx"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	_ "github.com/tealeg/xlsx"
	_ "gopkg.in/yaml.v2"
	_ "sort"
)

type User struct {
	gorm.Model
	Username string `form:"username" binding:"required"`
	Password string `form:"password" binding:"required"`
}

// SensorData là cấu trúc dữ liệu đại diện cho dữ liệu cảm biến
type SensorData struct {
	ID             int     `json:"id"`              // ID của dữ liệu cảm biến
	DeviceID       string  `json:"device_id"`       // ID thiết bị của dữ liệu cảm biến
	LightIntensity float64 `json:"light_intensity"` // Độ sáng cảm biến
	Temperature    float64 `json:"temperature"`     // Nhiệt độ cảm biến
	AirHumidity    float64 `json:"air_humidity"`    // Độ ẩm không khí
	SoilHumidity   float64 `json:"soil_humidity"`   // Độ ẩm đất
	Prediction     string  `json:"prediction"`      // Dự đoán
	Timestamp      string  `json:"timestamp"`       // Thời điểm ghi nhận dữ liệu
	Note           string  `json:"note"`            // Ghi chú
}

// UserControlData là cấu trúc dữ liệu đại diện cho dữ liệu điều khiển từ người dùng
type UserControlData struct {
	ID        int    `json:"id"`        // ID của dữ liệu điều khiển
	DeviceID  string `json:"device_id"` // ID thiết bị của dữ liệu điều khiển
	Command   string `json:"command"`   // Lệnh điều khiển
	Timestamp string `json:"timestamp"` // Thời điểm ghi nhận dữ liệu
}

// AddUserControlRequest là cấu trúc dữ liệu đại diện cho yêu cầu thêm dữ liệu điều khiển từ người dùng
type AddUserControlRequest struct {
	DeviceID  string `json:"device_id"` // ID thiết bị của dữ liệu điều khiển
	Command   string `json:"command"`   // Lệnh điều khiển
	Timestamp string `json:"timestamp"` // Thời điểm yêu cầu thêm dữ liệu
}

type CustomClaims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

var db *gorm.DB
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
var apiURL = "http://127.0.0.1:5000"

func main() {

	var err error
	db, err = gorm.Open("sqlite3", "database.db")
	if err != nil {
		log.Fatal("Failed to connect database:", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			log.Println("Error closing database:", cerr)
		}
	}()

	db.AutoMigrate(&User{})

	r := gin.Default()

	// Middleware
	r.Use(LoggerMiddleware)

	r.GET("/", loginsHandler)
	r.GET("/register", registerPageHandler)
	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)
	r.GET("/profile", AuthMiddleware, profileHandler)

	// Protected routes
	authenticated := r.Group("/authenticated")
	authenticated.Use(AuthMiddleware)
	{
		authenticated.GET("/profile", profileHandler)
	}

	r.GET("/download", downloadHandler)
	r.POST("/add_user_control", func(c *gin.Context) {
		addUserControlHandler(c.Writer, c.Request)
	})

	r.GET("/sensor", func(c *gin.Context) {
		latestSensorData, err := fetchLatestSensorData()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Error fetching latest sensor data"})
			return
		}

		latestUserControlData, err := fetchLatestUserControlData()
		if err != nil {
			c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Error fetching latest user control data"})
			return
		}

		// Merge both sets of data into a single gin.H
		data := gin.H{
			"LatestSensorData":      latestSensorData,
			"LatestUserControlData": latestUserControlData,
		}

		// Render the template with the merged data
		renderTemplate(c, "sensor.html", data)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	log.Printf("Listening on port %s", port)
	log.Printf("Open http://localhost:%s in the browser", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))
}

func loginsHandler(c *gin.Context) {
	renderTemplate(c, "login.html", nil)
}

func generateToken(userID uint, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token hết hạn sau 24 giờ

	claims := &CustomClaims{
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Println("Tạo token không thành công:", err)
		return "", err
	}

	return tokenString, nil
}

func registerPageHandler(c *gin.Context) {
	renderTemplate(c, "register.html", nil)
}

func setTokenCookie(c *gin.Context, token string) {
	c.SetCookie("token", token, int(time.Minute.Seconds()), "/", "localhost", false, true)
}

func registerHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBind(&user); err != nil {
		renderTemplate(c, "error.html", gin.H{"error": "Invalid input"})
		return
	}

	var existingUser User
	if err := db.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
		renderTemplate(c, "error.html", gin.H{"error": "Username already exists"})
		return
	}

	db.Create(&user)
	renderTemplate(c, "success.html", gin.H{"message": "Registration successful"})
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBind(&user); err != nil {
		renderTemplate(c, "error.html", gin.H{"error": "Invalid input"})
		return
	}

	var existingUser User
	if err := db.Where("username = ? AND password = ?", user.Username, user.Password).First(&existingUser).Error; err != nil {
		renderTemplate(c, "error.html", gin.H{"error": "Invalid username or password"})
		return
	}

	token, err := generateToken(existingUser.ID, "user") // replace "user" with the actual role
	if err != nil {
		renderTemplate(c, "error.html", gin.H{"error": "Failed to generate token"})
		return
	}
	setTokenCookie(c, token)
	// Print the token in the response
	//c.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": tokenString})
	renderTemplate(c, "page.html", nil)
}

func renderTemplate(c *gin.Context, name string, data interface{}) {
	tmpl, err := template.ParseFiles("templates/" + name)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Internal Server Error"})
		return
	}

	err = tmpl.Execute(c.Writer, data)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Internal Server Error"})
	}
}

func fetchSensorData() ([]SensorData, error) {
	apiURL := apiURL + "/get_sensor_data"

	// Thực hiện yêu cầu HTTP GET đến API để lấy dữ liệu cảm biến
	response, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// Xử lý lỗi nếu có khi đóng cơ thể yêu cầu HTTP
		}
	}(response.Body)

	// Kiểm tra xem yêu cầu có thành công không
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", response.Status)
	}

	// Giải mã dữ liệu JSON từ cơ thể yêu cầu và đưa vào slice sensorData
	var sensorData []SensorData
	err = json.NewDecoder(response.Body).Decode(&sensorData)
	if err != nil {
		return nil, err
	}

	return sensorData, nil
}

func fetchLatestSensorData() (SensorData, error) {
	sensorData, err := fetchSensorData()
	if err != nil {
		return SensorData{}, err
	}

	if len(sensorData) == 0 {
		return SensorData{}, fmt.Errorf("no sensor data available")
	}

	sort.Slice(sensorData, func(i, j int) bool {
		return sensorData[i].ID < sensorData[j].ID
	})

	return sensorData[len(sensorData)-1], nil
}

func addUserControl(deviceID, command string) error {
	apiURL := apiURL + "/add_user_control"

	// Tạo một yêu cầu điều khiển từ người dùng
	addUserControlReq := AddUserControlRequest{
		DeviceID:  deviceID,
		Command:   command,
		Timestamp: time.Now().In(time.FixedZone("UTC+7", 7*60*60)).Format("2006-01-02 15:04:05"),
	}

	// Chuyển cấu trúc yêu cầu thành dữ liệu JSON
	payload, err := json.Marshal(addUserControlReq)
	if err != nil {
		return err
	}

	// Thực hiện yêu cầu HTTP POST đến API để thêm dữ liệu điều khiển
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// Xử lý lỗi nếu có khi đóng cơ thể yêu cầu HTTP
		}
	}(resp.Body)

	// Kiểm tra xem yêu cầu có thành công không
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	return nil
}

func fetchUserControlData() ([]UserControlData, error) {
	apiURL := apiURL + "/get_user_control"

	// Thực hiện yêu cầu HTTP GET đến API để lấy dữ liệu điều khiển từ người dùng
	response, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// Xử lý lỗi nếu có khi đóng cơ thể yêu cầu HTTP
			log.Println("Error closing response body:", err)
		}
	}(response.Body)

	// Kiểm tra xem yêu cầu có thành công không
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", response.Status)
	}

	// Giải mã dữ liệu JSON từ cơ thể yêu cầu và đưa vào slice userControlData
	var userControlData []UserControlData
	err = json.NewDecoder(response.Body).Decode(&userControlData)
	if err != nil {
		return nil, err
	}

	return userControlData, nil
}

func fetchLatestUserControlData() (UserControlData, error) {
	// Gọi hàm fetchUserControlData để lấy dữ liệu điều khiển từ người dùng
	userControlData, err := fetchUserControlData()
	if err != nil {
		return UserControlData{}, err
	}

	// Nếu không có dữ liệu điều khiển từ người dùng, trả về lỗi "No user control data available"
	if len(userControlData) == 0 {
		return UserControlData{}, fmt.Errorf("no user control data available")
	}

	// Sắp xếp slice userControlData theo ID tăng dần để lấy dữ liệu điều khiển cuối cùng
	sort.Slice(userControlData, func(i, j int) bool {
		return userControlData[i].ID < userControlData[j].ID
	})

	// Trả về dữ liệu điều khiển cuối cùng trong slice
	return userControlData[len(userControlData)-1], nil
}

func addUserControlHandler(w http.ResponseWriter, r *http.Request) {
	// Get device ID and command from the form data
	deviceID := r.FormValue("device_id")
	command := r.FormValue("command")

	// Call addUserControl to add user control data and handle errors
	err := addUserControl(deviceID, command)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error adding user control data: %v", err), http.StatusInternalServerError)
		return
	}

	// Redirect the user to the main page "/" using 303 See Other
	http.Redirect(w, r, "/sensor", http.StatusSeeOther)
}

func downloadHandler(c *gin.Context) {
	// Lấy dữ liệu cảm biến từ API bằng cách gọi hàm fetchSensorData và xử lý lỗi nếu có
	sensorData, err := fetchSensorData()
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": fmt.Sprintf("Error fetching sensor data: %v", err)})
		return
	}

	// Kiểm tra nếu không có dữ liệu cảm biến, trả về lỗi "No sensor data available"
	if len(sensorData) == 0 {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "No sensor data available."})
		return
	}

	// Xuất dữ liệu cảm biến thành tệp tin Excel bằng cách gọi hàm exportSensorDataToExcel và xử lý lỗi nếu có
	err = exportSensorDataToExcel(c.Writer, sensorData)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": fmt.Sprintf("Error exporting sensor data: %v", err)})
		return
	}
}

func exportSensorDataToExcel(w http.ResponseWriter, sensorData []SensorData) error {
	// Tạo một tệp tin Excel mới
	file := xlsx.NewFile()
	sheet, err := file.AddSheet("SensorData")
	if err != nil {
		return err
	}

	// Định nghĩa các tiêu đề cột cho tệp tin Excel
	headers := []string{"ID", "DeviceID", "LightIntensity", "Temperature", "AirHumidity", "SoilHumidity", "Prediction", "Timestamp", "Note"}
	headerRow := sheet.AddRow()
	for _, header := range headers {
		cell := headerRow.AddCell()
		cell.Value = header
	}

	// Thêm dữ liệu cảm biến vào tệp tin Excel
	for _, data := range sensorData {
		row := sheet.AddRow()
		row.AddCell().SetInt(data.ID)
		row.AddCell().Value = data.DeviceID
		row.AddCell().SetFloat(data.LightIntensity)
		row.AddCell().SetFloat(data.Temperature)
		row.AddCell().SetFloat(data.AirHumidity)
		row.AddCell().SetFloat(data.SoilHumidity)
		row.AddCell().Value = data.Prediction
		row.AddCell().Value = data.Timestamp
		row.AddCell().Value = data.Note
	}

	// Đặt loại nội dung của phản hồi HTTP là Excel
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	// Đặt tên tệp tin để tải về
	w.Header().Set("Content-Disposition", "attachment; filename=sensor_data.xlsx")

	// Ghi tệp tin Excel vào phản hồi HTTP
	err = file.Write(w)
	if err != nil {
		return err
	}

	return nil
}

func profileHandler(c *gin.Context) {
	// Retrieve user ID from JWT claims
	claims, _ := c.Get("claims")
	userID := claims.(jwt.MapClaims)["user_id"].(float64)

	// Fetch user data from the database using the user ID
	var user User
	db.First(&user, uint(userID))

	renderTemplate(c, "profile.html", gin.H{"user": user})
}

// LoggerMiddleware Middleware for logging
func LoggerMiddleware(c *gin.Context) {
	start := time.Now()

	c.Next()

	// Log the request duration
	log.Printf("[%s] %s %s %v", c.Request.Method, c.Request.URL.Path, c.Request.Proto, time.Since(start))
}

// AuthMiddleware Middleware for JWT authentication
func AuthMiddleware(c *gin.Context) {
	tokenString, err := c.Cookie("token")
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/") // Chuyển hướng đến trang đăng nhập nếu không có token
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.Redirect(http.StatusSeeOther, "/") // Chuyển hướng đến trang đăng nhập nếu token không hợp lệ
		return
	}

	// Gắn claims vào context để sử dụng sau này
	claims := token.Claims.(*CustomClaims)
	c.Set("claims", claims)

	c.Next()
}
