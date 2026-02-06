#include <iostream>
#include <fstream>
#include <unordered_set>
#include <string>
#include <regex>
#include <algorithm>
#ifdef USE_JSON
#include "json.hpp"
#endif

using namespace std;


string clean(const string& s) {
    string out;
    for (char c : s) {
        if (!isspace(c)) out += tolower(c);
    }
    return out;
}


void load_passwords(const string& filename, unordered_set<string>& passwords) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Could not open file: " << filename << endl;
        return;
    }
    string line;
    while (getline(file, line)) {
        string pw = clean(line);
        if (!pw.empty()) passwords.insert(pw);
    }
    file.close();
}


bool has_repeated_chars(const string& password) {
    for (size_t i = 0; i + 2 < password.size(); ++i) {
        if (password[i] == password[i+1] && password[i] == password[i+2])
            return true;
    }
    return false;
}


struct PasswordResult {
    int score;
    string level;
    bool rules[7]; 
    bool hasRepeatedChars;
};

PasswordResult check_password_strength(const string& password,
                                       const unordered_set<string>& breached,
                                       const unordered_set<string>& common) {
    string pw = password;
    string pw_lower = pw;
    transform(pw_lower.begin(), pw_lower.end(), pw_lower.begin(), ::tolower);

    bool rules[7];
    rules[0] = pw.length() >= 8;
    rules[1] = regex_search(pw, regex("[A-Z]"));
    rules[2] = regex_search(pw, regex("[a-z]"));
    rules[3] = regex_search(pw, regex("[0-9]"));
    rules[4] = regex_search(pw, regex("[!@#$%^&*()_+\-=[\]{};':\"\\|,.<>/?]"));
    rules[5] = breached.find(pw_lower) == breached.end();// 
    rules[6] = common.find(pw_lower) == common.end();

    int score = 0;
    for (int i = 0; i < 7; ++i) if (rules[i]) ++score;
    bool repeated = has_repeated_chars(pw);
    if (repeated) --score;

    string level;
    if (!rules[5]) {
        level = "Breached Password";
        score = 0;
    } else if (!rules[6]) {
        level = "Common Password";
        score = 0;
    } else if (score <= 2) {
        level = "Very Weak";
    } else if (score <= 4) {
        level = "Weak";
    } else if (score <= 6) {
        level = "Medium";
    } else {
        level = "Strong";
    }

    return {score, level, {rules[0], rules[1], rules[2], rules[3], rules[4], rules[5], rules[6]}, repeated};
}

int main(int argc, char* argv[]) {
    unordered_set<string> breached, common;
    load_passwords("breachpassword.txt", breached);
    load_passwords("commonpassword_manageable.txt", common);

    string password;
    cout << "Enter password: ";
    getline(cin, password);

    const size_t MAX_PASSWORD_LENGTH = 32; 
    if (password.length() > MAX_PASSWORD_LENGTH) {
        cout << "This password exceeds the maximum allowed length of " << MAX_PASSWORD_LENGTH << " characters. Please choose a shorter password." << endl;
        return 1;
    }

    PasswordResult result = check_password_strength(password, breached, common);


    cout << "\nPassword Strength: " << result.level << endl;
    cout << "Score: " << result.score << "/7" << endl;
    cout << "Rules met:" << endl;
    cout << "  Length >= 8: " << (result.rules[0] ? "Yes" : "No") << endl;
    cout << "  Uppercase: " << (result.rules[1] ? "Yes" : "No") << endl;
    cout << "  Lowercase: " << (result.rules[2] ? "Yes" : "No") << endl;
    cout << "  Number: " << (result.rules[3] ? "Yes" : "No") << endl;
    cout << "  Special char: " << (result.rules[4] ? "Yes" : "No") << endl;
    cout << "  Not breached: " << (result.rules[5] ? "Yes" : "No") << endl;
    cout << "  Not common: " << (result.rules[6] ? "Yes" : "No") << endl;
    cout << "  Repeated chars: " << (result.hasRepeatedChars ? "Yes" : "No") << endl;

#ifdef USE_JSON
    nlohmann::json j;
    j["score"] = result.score;
    j["level"] = result.level;
    j["rules"] = {
        {"length", result.rules[0]},
        {"uppercase", result.rules[1]},
        {"lowercase", result.rules[2]},
        {"number", result.rules[3]},
        {"special", result.rules[4]},
        {"notBreached", result.rules[5]},
        {"notCommon", result.rules[6]}
    };
    j["hasRepeatedChars"] = result.hasRepeatedChars;
    cout << "\nJSON Output:\n" << j.dump(2) << endl;
#endif
    return 0;
} 
