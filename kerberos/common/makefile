BUILD_DIR = common/build
SRC_DIR = common/src
INC_DIR = common/include

SRC = $(wildcard $(SRC_DIR)/*.c)
INCLUDE = -I $(INC_DIR)
OBJ = $(SRC:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
CC = gcc

utils: $(OBJ)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(INCLUDE) -c $< -o $@

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)
