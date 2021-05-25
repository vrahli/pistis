#ifndef VALUE_H
#define VALUE_H

#include <vector>

class VALUE {
public:
    std::vector<unsigned int> val;
public:
    VALUE();
    VALUE(unsigned int num, unsigned int v);
    void next();

    std::string to_string();

    int size();

    friend std::ostream& operator<<(std::ostream& os, const VALUE &v);
    bool operator<(const VALUE& v) const;
};

#endif
