BIN_DIR = bin
SRC_DIR = auth-server
BUILD_DIR = auth-server/build
INC_DIR = common/include

TARGET = auth-server
SRC = $(wildcard $(SRC_DIR)/*.c)
INCLUDE = -I $(INC_DIR)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o) $(wildcard common/build/*.o)
CC = gcc

$(BIN_DIR)/$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(INCLUDE) -c $< -o $@

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
