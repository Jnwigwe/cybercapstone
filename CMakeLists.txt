cmake_minimum_required(VERSION 3.16)
project(MalwareScanner VERSION 2.5.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 packages
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)

# Optional: Charts module for future enhancements
find_package(Qt6 COMPONENTS Charts)

# Source files
set(SOURCES
    main.cpp
    mainwindow.cpp
    scannerwidget.cpp
    dashboardwidget.cpp
    quarantinewidget.cpp
    resultswidget.cpp
    scanengine.cpp
    quarantinemanager.cpp
)

# Header files
set(HEADERS
    mainwindow.h
    scannerwidget.h
    dashboardwidget.h
    quarantinewidget.h
    resultswidget.h
    scanengine.h
    quarantinemanager.h
    threattypes.h
)

# UI files
set(FORMS
    mainwindow.ui
)

# Resources
set(RESOURCES
    resources.qrc
)

# Create executable
if(WIN32)
    add_executable(${PROJECT_NAME} WIN32
        ${SOURCES}
        ${HEADERS}
        ${FORMS}
        ${RESOURCES}
    )
elseif(APPLE)
    add_executable(${PROJECT_NAME} MACOSX_BUNDLE
        ${SOURCES}
        ${HEADERS}
        ${FORMS}
        ${RESOURCES}
    )
else()
    add_executable(${PROJECT_NAME}
        ${SOURCES}
        ${HEADERS}
        ${FORMS}
        ${RESOURCES}
    )
endif()

# Link Qt libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
)

# Link Charts if available
if(Qt6Charts_FOUND)
    target_link_libraries(${PROJECT_NAME} PRIVATE Qt6::Charts)
endif()

# Set application properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER com.securitysolutions.malwarescanner
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

# Install rules
install(TARGETS ${PROJECT_NAME}
    BUNDLE DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Platform-specific installation
if(APPLE)
    install(CODE "
        include(BundleUtilities)
        fixup_bundle(\"\${CMAKE_INSTALL_PREFIX}/${PROJECT_NAME}.app\" \"\" \"\")
    ")
endif()




