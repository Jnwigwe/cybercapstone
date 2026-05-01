//Jacob Libres

#include <iostream>
#include <fstream>
#include <regex>
#include <string>

using namespace std;

int main(int argc, char* argv[]) 
{
    if (argc < 2) 
    {
        cout << "Usage: " << argv[0] << " <filename>\n";
        //Error if no file provided
        return 1;
    }

    //Store the input filename from the command-line arguments
    string filename = argv[1];

    //Open the file for reading
    ifstream file(filename);
    if (!file) 
    {
        cout << "Error: could not open " << filename << "\n";
        //Error if the file can not be opened
        return 1;
    }

    //Variable to hold each line read from the file
    string line;
    //Tracks the current line number
    int lineNum = 0;
     //Counter for how many issues were found
    int findings = 0;

    // Regular expressions for suspicious code patterns
    regex unsafeFunc("(strcpy|sprintf|gets)\\s*\\("); //Detect unsafe functions
    regex uncheckedStat("stat\\s*\\(");               //Detect calls to stat()
    regex globalVar("^\\s*(FILE|int|char)\\s+\\*?[A-Za-z_]+\\s*=\\s*NULL;"); //Detect global vars

    //Print header for the report
    cout << "=== Code Analysis Report for " << filename << " ===\n\n";

    //Read the file line by line
    while (getline(file, line)) 
    {
        lineNum++; //Increment line number for each line read

        //Check for unsafe function usage
        if (regex_search(line, unsafeFunc)) 
        {
            cout << "[Line " << lineNum << "] Unsafe function used (possible buffer overflow)\n";
            findings++;
        }

        //Check for unchecked calls to stat()
        if (regex_search(line, uncheckedStat)) 
        {
            cout << "[Line " << lineNum << "] Call to stat() — check if return value is handled\n";
            findings++;
        }

        //Check for global variable declarations
        if (regex_search(line, globalVar)) 
        {
            cout << "[Line " << lineNum << "] Global variable declared — may cause side effects\n";
            findings++;
        }
    }

    //If no issues were found, print a clean message
    if (findings == 0)
        cout << "No suspicious patterns detected.\n";

    //Print total number of findings
    cout << "\nTotal findings: " << findings << "\n";

    //Program ends successfully
    return 0;
}
