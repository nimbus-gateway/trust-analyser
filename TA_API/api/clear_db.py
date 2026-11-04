# SPDX-License-Identifier: GPL-3.0-only ( contact authors for upgrade consent )
# Trust Analyzer - A service to evaluate the trustworthiness of a system
# using five trust evaluation categories: security, resilience, reliability,
# threat exposure, and intentions. Output is a trust score (0-100) and a
# behavior type (normal, suspicious, compromised).
#
# Copyright (c) 2026 Pasindu Kurupparachchi <pasindu.kurupparachchi@mtu.ie>, Nimbus Research Centre, Munster Technological University
#
# This work is partially supported by the Horizon Europe TELEMETRY project,
# funded by the European Commission under grant number 101119747, and by the
# Science Foundation Ireland Centre Advance CRT under grant number 18/CRT/6222.
#
# Trust analyzer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (subject to
# explicit consent) any later version.
#
# This tool is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE or SATISFACTORY QUALITY or PERFORMANCE,
# comply with any description or regulatory standard, or are safe, accurate,
# up to date or complete. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see [https://www.gnu.org/licenses/.](https://www.gnu.org/licenses/)

import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# MongoDB connection details from environment variables
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "telemetry")

def clear_database():
    """
    Connects to MongoDB and drops the specified database.
    """
    try:
        # Establish a connection to the MongoDB server
        client = MongoClient(MONGO_URI)
        
        # Check if the database exists before trying to drop it
        if DB_NAME in client.list_database_names():
            # Drop the database
            client.drop_database(DB_NAME)
            print(f"Successfully dropped database: '{DB_NAME}'")
        else:
            print(f"Database '{DB_NAME}' does not exist. Nothing to do.")
            
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the client connection is closed
        if 'client' in locals() and client:
            client.close()

if __name__ == "__main__":
    # Ask for user confirmation before proceeding
    confirm = input(f"Are you sure you want to permanently delete all data in the '{DB_NAME}' database? (yes/no): ")
    if confirm.lower() == 'yes':
        clear_database()
    else:
        print("Operation cancelled.")

